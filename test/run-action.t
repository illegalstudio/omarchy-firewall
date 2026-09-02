#!/usr/bin/perl

use strict;
use warnings;

use File::Spec ();
use File::Temp qw(tempdir);
use FindBin ();
use IO::Select ();
use JSON::PP ();
use Test::More;
use Time::HiRes qw(time usleep);

my $supervisor = File::Spec->catfile(
  $FindBin::Bin,
  "..",
  "scripts",
  "run-action.pl",
);
do $supervisor or die "Cannot load $supervisor: $@ $!";

my $service_path = File::Spec->catfile($FindBin::Bin, "..", "Service.qml");
open(my $service_handle, "<", $service_path)
  or die "Cannot read $service_path: $!";
my $service_source;
{
  local $/;
  $service_source = <$service_handle>;
}
close($service_handle);

my @cleared_environments = $service_source =~ /clearEnvironment:\s*true/g;
is(scalar(@cleared_environments), 2,
  "both bundled Perl helpers clear the inherited environment");
my @minimal_environments = $service_source
  =~ /environment:\s*\(\{\s*LC_ALL:\s*"C"\s*\}\)/g;
is(scalar(@minimal_environments), 2,
  "both bundled Perl helpers receive only the fixed locale");
my @taint_invocations = $service_source =~ /"\/usr\/bin\/perl",\s*"-T"/g;
is(scalar(@taint_invocations), 2,
  "both bundled Perl helpers start in taint mode");

sub wait_for_process_stop {
  my ($pid) = @_;
  return 0 if !$pid;
  for (1 .. 20) {
    my $stat_path = "/proc/$pid/stat";
    my $stat;
    return 1 if !open($stat, "<", $stat_path);
    my $line = <$stat>;
    close($stat);
    my @fields = split(/\s+/, $line || "");
    return 1 if ($fields[2] || "") eq "Z";
    usleep(25_000);
  }
  return 0;
}

is_deeply(
  validate_ufw_args(["--force", "enable"]),
  ["--force", "enable"],
  "enable is an exact allowed operation",
);
is_deeply(
  validate_ufw_args(["allow", "in", "proto", "tcp", "from", "10.0.0.0/24", "to", "any", "port", "8000:8010"]),
  ["allow", "in", "proto", "tcp", "from", "10.0.0.0/24", "to", "any", "port", "8000:8010"],
  "structured rule grammar is rebuilt",
);
is_deeply(
  validate_ufw_args(["delete", "allow", "22/tcp"]),
  ["delete", "allow", "22/tcp"],
  "delete keeps an argv array",
);
eval { validate_ufw_args(["reset"]) };
like($@, qr/Unsupported ufw operation/, "unsafe operation is rejected");
eval { validate_ufw_args(["allow", "22\nreset"]) };
like($@, qr/control or non-ASCII/, "control characters are rejected");
eval { validate_ufw_args(["allow", "--force", "reset"]) };
like($@, qr/Flags are not allowed/, "flags cannot enter a rule operation");
eval { validate_ufw_args(["allow", "8000:8010"]) };
like($@, qr/Invalid ufw port or range/, "simple ranges require a protocol");
eval { validate_ufw_args(["allow", "from", "any", "to", "any", "port", "8000:8010"]) };
like($@, qr/requires a protocol/, "structured ranges require a protocol");
eval { validate_ufw_args(["allow", "22/tcp", "unexpected"]) };
like($@, qr/Unexpected ufw rule argument/, "trailing arguments are rejected");

my $privileged_command = build_privileged_command(["--force", "enable"]);
is_deeply(
  $privileged_command,
  [
    "/usr/bin/pkexec",
    "--disable-internal-agent",
    "/usr/bin/timeout",
    "--signal=TERM",
    "--kill-after=5s",
    "45s",
    "/usr/bin/ufw",
    "--force",
    "enable",
  ],
  "privileged argv has an exact root timeout and no internal auth fallback",
);

my $linked_executable = File::Spec->catfile($FindBin::Bin, "ufw-link-$$");
unlink($linked_executable);
symlink("/usr/bin/ufw", $linked_executable) or die "Cannot create executable symlink: $!";
eval { validate_system_executable($linked_executable) };
like($@, qr/non-regular executable/, "symlink executable is rejected");
unlink($linked_executable);

my $success = run_supervised([
  $^X,
  "-e",
  "print qq(action-ok); warn qq(action-note\\n);",
]);
ok($success->{valid}, "successful result is valid");
is($success->{exitCode}, 0, "successful child exit is preserved");
is($success->{stdout}, "action-ok", "stdout is captured");
like($success->{stderr}, qr/action-note/, "stderr is captured");
ok(!$success->{overflow}, "small output does not overflow");

my $ambient_library = tempdir(CLEANUP => 1);
open(my $ambient_module, ">", File::Spec->catfile($ambient_library, "AmbientStartup.pm"))
  or die "Cannot create ambient Perl module: $!";
print {$ambient_module} "package AmbientStartup; BEGIN { die qq(ambient module loaded\\n) } 1;\n";
close($ambient_module);
my $taint_startup;
{
  local $ENV{PERL5LIB} = $ambient_library;
  local $ENV{PERL5OPT} = "-MAmbientStartup";
  $taint_startup = run_supervised([
    "/usr/bin/perl",
    "-T",
    "-e",
    "print qq(clean-startup);",
  ]);
}
is($taint_startup->{exitCode}, 0,
  "taint startup ignores ambient Perl module controls");
is($taint_startup->{stdout}, "clean-startup",
  "ambient Perl modules cannot run before the script");

die "Unexpected test path" if $supervisor =~ /\}/;
my $taint_validator_program = 'do q{' . $supervisor
  . '}; my $safe = validate_ufw_args(\@ARGV);'
  . ' exec {q{/usr/bin/true}} q{/usr/bin/true}, @{$safe};';
my $taint_validator;
{
  local %ENV = (LC_ALL => "C");
  $taint_validator = run_supervised([
    "/usr/bin/perl",
    "-T",
    "-e",
    $taint_validator_program,
    "disable",
  ]);
}
is($taint_validator->{exitCode}, 0,
  "validated tainted argv is rebuilt safely for list-form exec");

my $overflow = run_supervised([
  $^X,
  "-e",
  "print qq(x) x 1024; warn qq(y) x 1024;",
], { stream_limit => 32 });
ok($overflow->{overflow}, "stream overflow is reported");
cmp_ok(length($overflow->{stdout}), "<=", 32, "stdout retention is capped");
cmp_ok(length($overflow->{stderr}), "<=", 32, "stderr retention is capped");
ok(length($overflow->{stdout}) == 32 || length($overflow->{stderr}) == 32,
  "one producer stream reached the enforced cap");

my $overflow_started = time();
my $endless_output = run_supervised([
  $^X,
  "-e",
  '$SIG{TERM} = "IGNORE"; $SIG{PIPE} = "IGNORE"; while (1) { print "z" x 4096; }',
], { timeout => 2, grace => 0.05, stream_limit => 64 });
ok($endless_output->{overflow}, "producer overflow is reported");
cmp_ok(time() - $overflow_started, "<", 1, "overflow stops the producer promptly");

my $overflow_tree = run_supervised([
  $^X,
  "-e",
  '$SIG{PIPE} = "IGNORE"; $| = 1; my $child = fork();'
    . ' die "fork failed" if !defined($child);'
    . ' if ($child == 0) { $SIG{TERM} = "IGNORE"; close(STDOUT); close(STDERR);'
    . ' select(undef, undef, undef, 5); exit 0; }'
    . ' print "$child\\n"; select(undef, undef, undef, 0.05);'
    . ' print "z" x 4096; select(undef, undef, undef, 5);',
], { timeout => 2, grace => 0.1, stream_limit => 64 });
my ($overflow_descendant) = $overflow_tree->{stdout} =~ /([0-9]+)/;
ok($overflow_tree->{overflow}, "descendant regression reaches the output limit");
ok($overflow_descendant, "overflow regression captures the closed-stream descendant");
ok(wait_for_process_stop($overflow_descendant),
  "supervisor proves the TERM-ignoring descendant is gone before returning");

my $started = time();
my $timed_out = run_supervised([
  $^X,
  "-e",
  '$SIG{TERM} = "IGNORE"; select(undef, undef, undef, 2);',
], { timeout => 0.05, grace => 0.05 });
my $elapsed = time() - $started;
ok($timed_out->{timedOut}, "deadline is reported");
ok($timed_out->{signal} != 0, "timed out child is terminated");
cmp_ok($elapsed, "<", 1, "timeout includes bounded termination grace");

my $root_timeout_shape = run_supervised([
  "/usr/bin/timeout",
  "--signal=TERM",
  "--kill-after=0.05s",
  "0.05s",
  $^X,
  "-e",
  '$SIG{TERM} = "IGNORE"; select(undef, undef, undef, 2);',
], { timeout => 2, grace => 0.05 });
ok(
  (defined($root_timeout_shape->{exitCode})
      && ($root_timeout_shape->{exitCode} == 124 || $root_timeout_shape->{exitCode} == 137))
    || $root_timeout_shape->{signal} == 9,
  "GNU timeout enforces TERM followed by KILL",
);

my $root_timeout_tree = run_supervised([
  "/usr/bin/timeout",
  "--signal=TERM",
  "--kill-after=0.05s",
  "0.05s",
  $^X,
  "-e",
  '$SIG{TERM} = "IGNORE"; $| = 1; my $child = fork();'
    . ' if ($child == 0) { $SIG{TERM} = "IGNORE"; select(undef, undef, undef, 5); exit 0; }'
    . ' print "$child\\n"; select(undef, undef, undef, 5);',
], { timeout => 2, grace => 0.05 });
my ($root_timeout_descendant) = $root_timeout_tree->{stdout} =~ /([0-9]+)/;
ok($root_timeout_descendant, "root-timeout shape captures a descendant pid");
ok(wait_for_process_stop($root_timeout_descendant),
  "GNU timeout stops descendants in its process group");

my $tree = run_supervised([
  $^X,
  "-e",
  '$SIG{TERM} = "IGNORE"; $| = 1; my $child = fork();'
    . ' if ($child == 0) { $SIG{TERM} = "IGNORE"; select(undef, undef, undef, 2); exit 0; }'
    . ' print "$child\\n"; select(undef, undef, undef, 2);',
], { timeout => 0.05, grace => 0.05 });
my ($descendant_pid) = $tree->{stdout} =~ /([0-9]+)/;
ok($descendant_pid, "process-tree test captures a descendant pid");
ok(wait_for_process_stop($descendant_pid),
  "timeout stops descendants in the action process group");

my $test_pid = $$;
my $signal_sender = fork();
die "Cannot fork signal sender: $!" if !defined($signal_sender);
if ($signal_sender == 0) {
  usleep(100_000);
  kill("TERM", $test_pid);
  exit 0;
}
my $interrupted = run_supervised([
  $^X,
  "-e",
  '$SIG{TERM} = "IGNORE"; select(undef, undef, undef, 2);',
], { timeout => 2, grace => 0.05 });
waitpid($signal_sender, 0);
ok($interrupted->{interrupted}, "supervisor interruption is reported");
ok($interrupted->{signal} != 0, "interruption terminates the child group");

pipe(my $loss_result_read, my $loss_result_write)
  or die "Cannot create owner-loss result pipe: $!";
pipe(my $loss_pid_read, my $loss_pid_write)
  or die "Cannot create owner-loss pid pipe: $!";
my $launcher_pid = fork();
die "Cannot fork owner-loss launcher: $!" if !defined($launcher_pid);
if ($launcher_pid == 0) {
  close($loss_result_read);
  close($loss_pid_read);
  my $worker_pid = fork();
  POSIX::_exit(125) if !defined($worker_pid);
  if ($worker_pid == 0) {
    close($loss_pid_write);
    my $result = run_supervised([
      $^X,
      "-e",
      '$SIG{TERM} = "IGNORE"; select(undef, undef, undef, 5);',
    ], { timeout => 4, grace => 0.05 });
    print {$loss_result_write} JSON::PP->new->canonical->encode($result);
    close($loss_result_write);
    POSIX::_exit(0);
  }
  print {$loss_pid_write} "$worker_pid\n";
  close($loss_pid_write);
  close($loss_result_write);
  select(undef, undef, undef, 5);
  POSIX::_exit(0);
}
close($loss_result_write);
close($loss_pid_write);
my $worker_pid_line = <$loss_pid_read>;
close($loss_pid_read);
ok($worker_pid_line && $worker_pid_line =~ /\A[0-9]+\n\z/,
  "owner-loss test started a supervisor worker");
kill("TERM", $launcher_pid);
waitpid($launcher_pid, 0);
my $loss_selector = IO::Select->new($loss_result_read);
my $owner_loss_payload;
if ($loss_selector->can_read(2)) {
  local $/;
  my $json = <$loss_result_read>;
  $owner_loss_payload = eval { JSON::PP->new->decode($json || "") };
}
close($loss_result_read);
ok($owner_loss_payload && $owner_loss_payload->{interrupted},
  "loss of the owning process interrupts supervision");
ok($owner_loss_payload && $owner_loss_payload->{signal},
  "owner loss terminates the supervised process group");

my $encoded = encode_bounded_result({
  valid  => JSON::PP::true,
  stdout => "x" x (MAX_RESULT_BYTES() + 1),
});
my $decoded = JSON::PP->new->utf8->decode($encoded);
ok(!$decoded->{valid}, "oversized supervisor JSON fails closed");
ok(length($encoded) <= MAX_RESULT_BYTES(), "supervisor JSON stays bounded");

done_testing;
