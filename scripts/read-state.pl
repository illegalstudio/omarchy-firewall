#!/usr/bin/perl

use strict;
use warnings;

use Encode qw(decode FB_DEFAULT);
use Fcntl qw(FD_CLOEXEC F_SETFD O_NOFOLLOW O_RDONLY S_ISDIR S_ISREG);
use File::Spec ();
use JSON::PP ();

use constant MAX_CONF_BYTES         => 16 * 1024;
use constant MAX_DEFAULTS_BYTES     => 64 * 1024;
use constant MAX_RULES_BYTES        => 2 * 1024 * 1024;
use constant MAX_PROFILE_ENTRIES    => 256;
use constant MAX_PROFILE_FILES      => 128;
use constant MAX_PROFILE_FILE_BYTES => 64 * 1024;
use constant MAX_PROFILES           => 256;
use constant MAX_OUTPUT_BYTES       => 6 * 1024 * 1024;

my %DEFAULT_PATHS = (
  conf        => "/etc/ufw/ufw.conf",
  defaults    => "/etc/default/ufw",
  rules4      => "/etc/ufw/user.rules",
  rules6      => "/etc/ufw/user6.rules",
  profile_dir => "/etc/ufw/applications.d",
);

sub _clean_error {
  my ($message) = @_;
  $message = "$message";
  $message =~ s/\s+/ /g;
  $message =~ s/^\s+|\s+$//g;
  return length($message) > 240 ? substr($message, 0, 237) . "..." : $message;
}

sub read_bounded_file {
  my ($path, $limit, $missing_ok) = @_;
  my $flags = O_RDONLY | O_NOFOLLOW;
  my $handle;

  if (!sysopen($handle, $path, $flags)) {
    return undef if $missing_ok && $!{ENOENT};
    die "Cannot open $path: $!";
  }

  fcntl($handle, F_SETFD, FD_CLOEXEC)
    or die "Cannot set close-on-exec for $path: $!";
  binmode($handle, ":raw");
  my @stat = stat($handle);
  die "Cannot stat $path: $!" if !@stat;
  die "Refusing non-regular file $path" if !S_ISREG($stat[2]);
  die "File exceeds $limit bytes: $path" if $stat[7] > $limit;

  my $bytes = "";
  while (length($bytes) <= $limit) {
    my $remaining = $limit + 1 - length($bytes);
    last if $remaining <= 0;
    my $chunk = "";
    my $wanted = $remaining > 64 * 1024 ? 64 * 1024 : $remaining;
    my $read = sysread($handle, $chunk, $wanted);
    die "Cannot read $path: $!" if !defined($read);
    last if $read == 0;
    $bytes .= $chunk;
  }

  close($handle) or die "Cannot close $path: $!";
  die "File exceeds $limit bytes: $path" if length($bytes) > $limit;
  return $bytes;
}

sub _decode_text {
  my ($bytes) = @_;
  return "" if !defined($bytes) || $bytes eq "";
  return decode("UTF-8", $bytes, FB_DEFAULT);
}

sub read_profiles {
  my ($directory) = @_;
  my @directory_stat = lstat($directory);
  return [] if !@directory_stat && $!{ENOENT};
  die "Cannot inspect $directory: $!" if !@directory_stat;
  die "Refusing non-directory $directory" if !S_ISDIR($directory_stat[2]);

  opendir(my $dir_handle, $directory) or die "Cannot open $directory: $!";
  my @entries;
  while (defined(my $entry = readdir($dir_handle))) {
    next if $entry eq "." || $entry eq "..";
    die "Profile directory exceeds " . MAX_PROFILE_ENTRIES . " entries"
      if @entries >= MAX_PROFILE_ENTRIES;
    push @entries, $entry;
  }
  closedir($dir_handle) or die "Cannot close $directory: $!";

  my %seen;
  my @profiles;
  my $file_count = 0;
  for my $entry (sort @entries) {
    my $path = File::Spec->catfile($directory, $entry);
    my @entry_stat = lstat($path);
    next if !@entry_stat || !S_ISREG($entry_stat[2]);
    die "Profile directory exceeds " . MAX_PROFILE_FILES . " regular files"
      if ++$file_count > MAX_PROFILE_FILES;

    my $text = _decode_text(read_bounded_file(
      $path,
      MAX_PROFILE_FILE_BYTES,
      0,
    ));

    for my $line (split(/\r?\n/, $text, -1)) {
      next if $line !~ /^[ \t]*\[([^\]\r\n]{1,64})\][ \t]*$/;
      my $name = $1;
      next if $name !~ /^[A-Za-z0-9][A-Za-z0-9 ._+\-]{0,63}$/;
      next if $seen{$name}++;
      die "Profile count exceeds " . MAX_PROFILES if @profiles >= MAX_PROFILES;
      push @profiles, $name;
    }
  }

  return [sort @profiles];
}

sub build_snapshot {
  my ($paths) = @_;
  $paths ||= \%DEFAULT_PATHS;

  my $conf_bytes = read_bounded_file($paths->{conf}, MAX_CONF_BYTES, 1);
  if (!defined($conf_bytes)) {
    return {
      ok        => JSON::PP::true,
      installed => JSON::PP::false,
      conf      => "",
      defaults  => "",
      rules4    => "",
      rules6    => "",
      profiles  => [],
    };
  }

  return {
    ok        => JSON::PP::true,
    installed => JSON::PP::true,
    conf      => _decode_text($conf_bytes),
    defaults  => _decode_text(read_bounded_file(
      $paths->{defaults},
      MAX_DEFAULTS_BYTES,
      1,
    )),
    rules4    => _decode_text(read_bounded_file(
      $paths->{rules4},
      MAX_RULES_BYTES,
      1,
    )),
    rules6    => _decode_text(read_bounded_file(
      $paths->{rules6},
      MAX_RULES_BYTES,
      1,
    )),
    profiles  => read_profiles($paths->{profile_dir}),
  };
}

sub encode_bounded_payload {
  my ($payload) = @_;
  my $json = JSON::PP->new->utf8->canonical->encode($payload);
  if (length($json) > MAX_OUTPUT_BYTES) {
    $json = JSON::PP->new->utf8->canonical->encode({
      ok    => JSON::PP::false,
      error => "Bounded state payload exceeds " . MAX_OUTPUT_BYTES . " bytes",
    });
  }
  return $json;
}

sub main {
  my $payload;
  my $ok = eval {
    $payload = build_snapshot(\%DEFAULT_PATHS);
    1;
  };

  if (!$ok) {
    $payload = {
      ok    => JSON::PP::false,
      error => _clean_error($@ || "Unknown state reader failure"),
    };
  }

  binmode(STDOUT, ":raw");
  print STDOUT encode_bounded_payload($payload);
}

main() if !caller;

1;
