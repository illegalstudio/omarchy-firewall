#!/usr/bin/perl

use strict;
use warnings;

use Encode qw(decode FB_DEFAULT);
use Errno qw(EACCES EAGAIN ECHILD EINTR ESRCH EWOULDBLOCK);
use Fcntl qw(FD_CLOEXEC F_GETFL F_SETFD O_NONBLOCK S_ISDIR S_ISREG);
use IO::Select ();
use JSON::PP ();
use POSIX qw(:sys_wait_h setpgid);
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime);

use constant MAX_ARGUMENTS       => 24;
use constant MAX_ARGUMENT_BYTES  => 256;
use constant MAX_STREAM_BYTES    => 4096;
use constant MAX_RESULT_BYTES    => 16 * 1024;
use constant ACTION_TIMEOUT_SEC  => 90;
use constant TERM_GRACE_SEC      => 2;
use constant ROOT_TIMEOUT_SEC    => 45;
use constant ROOT_KILL_GRACE_SEC => 5;

my @TRUSTED_EXECUTABLES = (
  "/usr/bin/pkexec",
  "/usr/bin/timeout",
  "/usr/bin/ufw",
);

sub _clean_error {
  my ($message) = @_;
  $message = "$message";
  $message =~ s/\s+/ /g;
  $message =~ s/^\s+|\s+$//g;
  return length($message) > 240 ? substr($message, 0, 237) . "..." : $message;
}

sub _valid_port {
  my ($value) = @_;
  return defined($value) && $value =~ /\A[0-9]{1,5}\z/
    && int($value) >= 1 && int($value) <= 65535;
}

sub _valid_port_spec {
  my ($value, $protocol_required_for_range) = @_;
  return 0 if !defined($value);
  my ($ports, $protocol) = $value =~ /\A([0-9]{1,5}(?::[0-9]{1,5})?)(?:\/(tcp|udp))?\z/;
  return 0 if !defined($ports);
  my @ends = split(/:/, $ports, -1);
  return 0 if grep { !_valid_port($_) } @ends;
  return 0 if @ends == 2 && int($ends[0]) > int($ends[1]);
  return 0 if @ends == 2 && $protocol_required_for_range && !defined($protocol);
  return 1;
}

sub _valid_plain_port_spec {
  my ($value) = @_;
  return 0 if !defined($value)
    || $value !~ /\A([0-9]{1,5})(?::([0-9]{1,5}))?\z/;
  my ($first, $last) = ($1, $2);
  return 0 if !_valid_port($first);
  return 1 if !defined($last);
  return _valid_port($last) && int($first) <= int($last);
}

sub _valid_address {
  my ($value) = @_;
  return 1 if defined($value) && $value eq "any";
  return 0 if !defined($value);

  my $slash_count = () = $value =~ m{/}g;
  return 0 if $slash_count > 1;
  my ($address, $mask) = split(/\//, $value, -1);
  return 0 if defined($mask) && $mask !~ /\A[0-9]{1,3}\z/;

  if ($address =~ /:/) {
    return 0 if defined($mask) && int($mask) > 128;
    return $address =~ /\A[0-9A-Fa-f:.]+\z/ ? 1 : 0;
  }

  return 0 if defined($mask) && int($mask) > 32;
  my @octets = split(/\./, $address, -1);
  return 0 if @octets != 4;
  return !(grep { $_ !~ /\A[0-9]{1,3}\z/ || int($_) > 255 } @octets);
}

sub _validate_rule_spec {
  my ($tokens) = @_;
  my @input = @$tokens;
  my @safe;
  my $index = 0;

  if ($index < @input && ($input[$index] eq "in" || $input[$index] eq "out")) {
    push @safe, $input[$index++];
  }
  die "Incomplete ufw rule" if $index >= @input;

  if ($input[$index] eq "proto" || $input[$index] eq "from" || $input[$index] eq "to") {
    my $has_protocol = 0;
    if ($input[$index] eq "proto") {
      push @safe, $input[$index++];
      $has_protocol = 1;
      die "Incomplete ufw protocol" if $index >= @input;
      die "Unsupported ufw protocol" if $input[$index] ne "tcp" && $input[$index] ne "udp";
      push @safe, $input[$index++];
    }

    my $endpoints = 0;
    for my $keyword ("from", "to") {
      next if $index >= @input || $input[$index] ne $keyword;
      push @safe, $input[$index++];
      die "Incomplete ufw endpoint" if $index >= @input;
      die "Invalid ufw address" if !_valid_address($input[$index]);
      push @safe, $input[$index++];
      if ($index < @input && $input[$index] eq "port") {
        push @safe, $input[$index++];
        die "Incomplete ufw port" if $index >= @input;
        die "Invalid ufw port" if !_valid_plain_port_spec($input[$index]);
        die "A ufw port range requires a protocol"
          if $input[$index] =~ /:/ && !$has_protocol;
        push @safe, $input[$index++];
      }
      $endpoints++;
    }
    die "Ufw rule has no endpoint" if !$endpoints;
  } else {
    my $value = $input[$index++];
    if ($value =~ /\A[0-9]/) {
      die "Invalid ufw port or range" if !_valid_port_spec($value, 1);
    } else {
      die "Invalid ufw application profile"
        if $value !~ /\A[A-Za-z0-9][A-Za-z0-9 ._+\-]{0,63}\z/;
    }
    push @safe, $value;
  }

  if ($index < @input && $input[$index] eq "comment") {
    push @safe, $input[$index++];
    die "Incomplete ufw comment" if $index >= @input;
    my $comment = $input[$index++];
    die "Invalid ufw comment"
      if $comment !~ /\A[A-Za-z0-9 ._:\@\/+()\-]{1,120}\z/;
    push @safe, $comment;
  }

  die "Unexpected ufw rule argument" if $index != @input;
  return \@safe;
}

sub validate_ufw_args {
  my ($args) = @_;
  die "No ufw operation supplied" if ref($args) ne "ARRAY" || !@$args;
  die "Too many ufw arguments" if @$args > MAX_ARGUMENTS;

  my @input;
  for my $arg (@$args) {
    die "Invalid ufw argument" if !defined($arg);
    my $value = "$arg";
    die "Ufw argument exceeds " . MAX_ARGUMENT_BYTES . " bytes"
      if length($value) > MAX_ARGUMENT_BYTES;
    die "Ufw argument contains a control or non-ASCII character"
      if $value =~ /[^\x20-\x7e]/;
    push @input, $value;
  }

  return [@input] if @input == 2 && $input[0] eq "--force" && $input[1] eq "enable";
  die "Flags are not allowed for this ufw operation"
    if grep { /^-/ } @input;
  return [@input] if @input == 1 && ($input[0] eq "disable" || $input[0] eq "reload");

  my @safe;
  push @safe, shift @input if $input[0] eq "delete";
  die "Unsupported ufw operation" if !@input
    || $input[0] !~ /\A(?:allow|deny|reject|limit)\z/;
  push @safe, shift @input;
  die "Incomplete ufw rule" if !@input;
  push @safe, @{_validate_rule_spec(\@input)};
  return \@safe;
}

sub validate_system_executable {
  my ($path) = @_;
  my @stat = lstat($path);
  die "Missing required executable: $path" if !@stat;
  die "Refusing non-regular executable: $path" if !S_ISREG($stat[2]);
  die "Required executable is not root-owned: $path" if $stat[4] != 0;
  die "Required executable is writable outside root: $path" if ($stat[2] & 0022) != 0;
  die "Required executable is not executable: $path" if ($stat[2] & 0111) == 0;
  return 1;
}

sub validate_system_directory {
  my ($path) = @_;
  my @stat = lstat($path);
  die "Missing required system directory: $path" if !@stat;
  die "Refusing non-directory system path: $path" if !S_ISDIR($stat[2]);
  die "Required system directory is not root-owned: $path" if $stat[4] != 0;
  die "Required system directory is writable outside root: $path" if ($stat[2] & 0022) != 0;
  return 1;
}

sub build_privileged_command {
  my ($args, $paths) = @_;
  $paths ||= \@TRUSTED_EXECUTABLES;
  my $safe = validate_ufw_args($args);
  validate_system_directory($_) for ("/usr", "/usr/bin");
  validate_system_executable($_) for @$paths;

  return [
    "/usr/bin/pkexec",
    "--disable-internal-agent",
    "/usr/bin/timeout",
    "--signal=TERM",
    "--kill-after=" . ROOT_KILL_GRACE_SEC . "s",
    ROOT_TIMEOUT_SEC . "s",
    "/usr/bin/ufw",
    @$safe,
  ];
}

sub _set_cloexec {
  my ($handle) = @_;
  fcntl($handle, F_SETFD, FD_CLOEXEC) or die "Cannot set close-on-exec: $!";
}

sub _set_nonblocking {
  my ($handle) = @_;
  my $flags = fcntl($handle, Fcntl::F_GETFL(), 0);
  die "Cannot read descriptor flags: $!" if !defined($flags);
  fcntl($handle, Fcntl::F_SETFL(), $flags | O_NONBLOCK)
    or die "Cannot set nonblocking mode: $!";
}

sub _signal_group {
  my ($signal, $pid) = @_;
  my $sent = kill($signal, -$pid);
  kill($signal, $pid) if !$sent;
}

sub _append_bounded {
  my ($target, $chunk, $limit, $overflow_ref) = @_;
  my $remaining = $limit - length($$target);
  if ($remaining <= 0) {
    $$overflow_ref = 1;
    return 1;
  }
  if (length($chunk) > $remaining) {
    $$target .= substr($chunk, 0, $remaining);
    $$overflow_ref = 1;
    return 1;
  }
  $$target .= $chunk;
  return 0;
}

sub run_supervised {
  my ($command, $options) = @_;
  $options ||= {};
  die "Command must be a non-empty array" if ref($command) ne "ARRAY" || !@$command;

  my $timeout = defined($options->{timeout})
    ? $options->{timeout} : ACTION_TIMEOUT_SEC;
  my $grace = defined($options->{grace})
    ? $options->{grace} : TERM_GRACE_SEC;
  my $stream_limit = defined($options->{stream_limit})
    ? $options->{stream_limit} : MAX_STREAM_BYTES;
  die "Invalid process deadline" if $timeout <= 0 || $grace < 0 || $stream_limit < 1;
  my $original_parent = getppid();

  pipe(my $stdout_read, my $stdout_write) or die "Cannot create stdout pipe: $!";
  pipe(my $stderr_read, my $stderr_write) or die "Cannot create stderr pipe: $!";
  _set_cloexec($_) for ($stdout_read, $stdout_write, $stderr_read, $stderr_write);

  my $received_signal = "";
  local $SIG{TERM} = sub { $received_signal = "TERM"; };
  local $SIG{INT} = sub { $received_signal = "INT"; };
  local $SIG{HUP} = sub { $received_signal = "HUP"; };

  my $pid = fork();
  die "Cannot fork action supervisor: $!" if !defined($pid);

  if ($pid == 0) {
    $SIG{TERM} = "DEFAULT";
    $SIG{INT} = "DEFAULT";
    $SIG{HUP} = "DEFAULT";
    close($stdout_read);
    close($stderr_read);
    defined(setpgid(0, 0)) or POSIX::_exit(125);
    open(STDOUT, ">&", $stdout_write) or POSIX::_exit(125);
    open(STDERR, ">&", $stderr_write) or POSIX::_exit(125);
    close($stdout_write);
    close($stderr_write);
    no warnings "exec";
    exec {$command->[0]} @$command;
    print STDERR "Cannot execute $command->[0]: $!\n";
    POSIX::_exit(127);
  }

  close($stdout_write);
  close($stderr_write);
  my $setup_ok = eval {
    my $group_result = setpgid($pid, $pid);
    die "Cannot create action process group: $!"
      if !defined($group_result) && !$!{EACCES} && !$!{ESRCH};
    _set_nonblocking($stdout_read);
    _set_nonblocking($stderr_read);
    1;
  };
  if (!$setup_ok) {
    my $setup_error = $@ || "Cannot initialise action supervision";
    _signal_group("TERM", $pid);
    select(undef, undef, undef, $grace);
    _signal_group("KILL", $pid);
    waitpid($pid, 0);
    close($stdout_read);
    close($stderr_read);
    die $setup_error;
  }

  my $selector = IO::Select->new($stdout_read, $stderr_read);
  my %stream_for = (
    fileno($stdout_read) => "stdout",
    fileno($stderr_read) => "stderr",
  );
  my $stdout = "";
  my $stderr = "";
  my $stdout_overflow = 0;
  my $stderr_overflow = 0;
  my $started = clock_gettime(CLOCK_MONOTONIC);
  my $term_at;
  my $kill_sent = 0;
  my $timed_out = 0;
  my $interrupted = 0;
  my $runtime_error = "";
  my $child_done = 0;
  my $wait_status = 0;

  while (1) {
    my $now = clock_gettime(CLOCK_MONOTONIC);
    if (!defined($term_at) && getppid() != $original_parent) {
      $interrupted = 1;
      $term_at = $now;
      _signal_group("TERM", $pid);
    } elsif (!defined($term_at) && $received_signal ne "") {
      $interrupted = 1;
      $term_at = $now;
      _signal_group("TERM", $pid);
    } elsif (!defined($term_at) && $now - $started >= $timeout) {
      $timed_out = 1;
      $term_at = $now;
      _signal_group("TERM", $pid);
    } elsif (defined($term_at) && !$kill_sent && $now - $term_at >= $grace) {
      $kill_sent = 1;
      _signal_group("KILL", $pid);
    }

    my $output_limit_hit = 0;
    for my $handle ($selector->can_read(0.05)) {
      my $chunk = "";
      my $read = sysread($handle, $chunk, 16 * 1024);
      if (!defined($read)) {
        next if $!{EAGAIN} || $!{EWOULDBLOCK} || $!{EINTR};
        $runtime_error = "Cannot read action output: $!";
        if (!defined($term_at)) {
          $term_at = $now;
          _signal_group("TERM", $pid);
        }
        $selector->remove($handle);
        close($handle);
        next;
      }
      if ($read == 0) {
        $selector->remove($handle);
        close($handle);
        next;
      }
      if ($stream_for{fileno($handle)} eq "stdout") {
        $output_limit_hit = _append_bounded(
          \$stdout, $chunk, $stream_limit, \$stdout_overflow);
      } else {
        $output_limit_hit = _append_bounded(
          \$stderr, $chunk, $stream_limit, \$stderr_overflow);
      }
      last if $output_limit_hit;
    }

    if ($output_limit_hit) {
      for my $handle ($selector->handles) {
        $selector->remove($handle);
        close($handle);
      }
      if (!defined($term_at)) {
        $term_at = $now;
        _signal_group("TERM", $pid);
      }
    }

    if (!$child_done) {
      my $waited = waitpid($pid, WNOHANG);
      if ($waited == $pid) {
        $wait_status = $?;
        $child_done = 1;
      } elsif ($waited == -1) {
        if (!$!{ECHILD}) {
          $runtime_error = "Cannot wait for action process: $!";
          if (!defined($term_at)) {
            $term_at = $now;
            _signal_group("TERM", $pid);
          }
        }
        $child_done = 1;
      }
    }
    last if $child_done && $selector->count == 0;
  }

  die $runtime_error if $runtime_error ne "";

  my $exit_code = WIFEXITED($wait_status) ? WEXITSTATUS($wait_status) : undef;
  my $signal = WIFSIGNALED($wait_status) ? WTERMSIG($wait_status) : 0;
  return {
    valid       => JSON::PP::true,
    exitCode    => $exit_code,
    signal      => $signal,
    timedOut    => $timed_out ? JSON::PP::true : JSON::PP::false,
    interrupted => $interrupted ? JSON::PP::true : JSON::PP::false,
    overflow    => ($stdout_overflow || $stderr_overflow)
      ? JSON::PP::true : JSON::PP::false,
    stdout      => decode("UTF-8", $stdout, FB_DEFAULT),
    stderr      => decode("UTF-8", $stderr, FB_DEFAULT),
  };
}

sub encode_bounded_result {
  my ($payload) = @_;
  my $json = JSON::PP->new->utf8->canonical->encode($payload);
  if (length($json) > MAX_RESULT_BYTES) {
    $json = JSON::PP->new->utf8->canonical->encode({
      valid => JSON::PP::false,
      error => "Action result exceeded its safety limit",
    });
  }
  return $json;
}

sub main {
  my $payload;
  my $ok = eval {
    my $command = build_privileged_command(\@ARGV);
    $payload = run_supervised($command);
    $payload->{privilegedTimedOut} = !$payload->{timedOut} && !$payload->{interrupted}
      && ((defined($payload->{exitCode})
          && ($payload->{exitCode} == 124 || $payload->{exitCode} == 137))
        || $payload->{signal} == 9)
      ? JSON::PP::true : JSON::PP::false;
    1;
  };
  if (!$ok) {
    $payload = {
      valid => JSON::PP::false,
      error => _clean_error($@ || "Unknown action supervisor failure"),
    };
  }

  binmode(STDOUT, ":raw");
  print STDOUT encode_bounded_result($payload);
}

main() if !caller;

1;
