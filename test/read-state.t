#!/usr/bin/perl

use strict;
use warnings;

use File::Path qw(make_path);
use File::Spec ();
use File::Temp qw(tempdir);
use FindBin ();
use JSON::PP ();
use Test::More;

my $reader = File::Spec->catfile(
  $FindBin::Bin,
  "..",
  "scripts",
  "read-state.pl",
);
do $reader or die "Cannot load $reader: $@ $!";

sub fixture_bytes {
  my ($name) = @_;
  my $path = File::Spec->catfile($FindBin::Bin, "fixtures", $name);
  open(my $handle, "<:raw", $path) or die "Cannot open $path: $!";
  local $/;
  my $bytes = <$handle>;
  close($handle) or die "Cannot close $path: $!";
  return $bytes;
}

sub write_bytes {
  my ($path, $bytes) = @_;
  open(my $handle, ">:raw", $path) or die "Cannot create $path: $!";
  print {$handle} $bytes;
  close($handle) or die "Cannot close $path: $!";
}

my $temporary = tempdir(CLEANUP => 1);
my $profiles = File::Spec->catdir($temporary, "applications.d");
make_path($profiles);

my %paths = (
  conf        => File::Spec->catfile($temporary, "ufw.conf"),
  defaults    => File::Spec->catfile($temporary, "default-ufw"),
  rules4      => File::Spec->catfile($temporary, "user.rules"),
  rules6      => File::Spec->catfile($temporary, "user6.rules"),
  profile_dir => $profiles,
);

write_bytes($paths{conf}, fixture_bytes("ufw.conf"));
write_bytes($paths{defaults}, fixture_bytes("default-ufw"));
write_bytes($paths{rules4}, fixture_bytes("user.rules"));
write_bytes($paths{rules6}, fixture_bytes("user6.rules"));
write_bytes(
  File::Spec->catfile($profiles, "test-profiles"),
  fixture_bytes("applications.ini"),
);

my $snapshot = build_snapshot(\%paths);
ok($snapshot->{ok}, "fixture snapshot succeeds");
ok($snapshot->{installed}, "fixture snapshot reports ufw installed");
like($snapshot->{conf}, qr/^ENABLED=yes/m, "configuration is read");
like($snapshot->{rules4}, qr/^### tuple ###/m, "IPv4 tuples are read");
unlike($snapshot->{rules4}, qr/^-A /m, "non-tuple rule lines stay out of QML");
like($snapshot->{rulesDigest}, qr/\A[0-9a-f]{64}\z/, "rule digest is fixed-size");
ok(
  scalar(grep { $_ eq "Web Server" } @{$snapshot->{profiles}}),
  "application profiles are discovered",
);

my $oversized = File::Spec->catfile($temporary, "oversized");
write_bytes($oversized, "x" x 33);
eval { read_bounded_file($oversized, 32, 0) };
like($@, qr/exceeds 32 bytes/, "oversized files are rejected");

my $symlink = File::Spec->catfile($temporary, "linked");
symlink($paths{conf}, $symlink) or die "Cannot create test symlink: $!";
eval { read_bounded_file($symlink, 1024, 0) };
like($@, qr/Cannot open/, "symbolic links are rejected");

SKIP: {
  skip "host executable check requires an Omarchy system", 1
    if $ENV{OMARCHY_FIREWALL_SKIP_HOST_TOOL_CHECK};
  my ($tools_ready, $tools_error) = inspect_action_tools();
  ok($tools_ready, "installed action executables pass ownership checks")
    or diag($tools_error);
}
my $tool_link = File::Spec->catfile($temporary, "ufw-link");
symlink("/usr/bin/ufw", $tool_link) or die "Cannot create executable symlink: $!";
my ($linked_tool_ready, $linked_tool_error) = inspect_action_tools([$tool_link]);
ok(!$linked_tool_ready, "symbolic-link action executable is rejected");
like($linked_tool_error, qr/non-regular executable/, "tool rejection is explicit");

my $first_digest = $snapshot->{rulesDigest};
write_bytes(
  $paths{rules4},
  fixture_bytes("user.rules")
    . "### tuple ### allow tcp 65530 0.0.0.0/0 any 0.0.0.0/0 in\n",
);
my $changed_snapshot = build_snapshot(\%paths);
isnt($changed_snapshot->{rulesDigest}, $first_digest, "rule digest changes with persisted tuples");
write_bytes($paths{rules4}, fixture_bytes("user.rules"));

my $crowded_rules = File::Spec->catfile($temporary, "crowded.rules");
write_bytes(
  $crowded_rules,
  scalar(("### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in\n")
    x (MAX_RULE_RECORDS() + 1)),
);
eval { read_bounded_rules($crowded_rules, 0) };
my $crowded_rules_error = $@;
like($crowded_rules_error, qr/Rule count exceeds 512 records/, "rule record count is bounded");

my $too_many_lines = File::Spec->catfile($temporary, "many-lines.rules");
write_bytes($too_many_lines, scalar("#\n" x (MAX_RULE_LINES() + 1)));
eval { read_bounded_rules($too_many_lines, 0) };
my $too_many_lines_error = $@;
like($too_many_lines_error, qr/Rule file exceeds 8192 lines/, "rule line count is bounded");

my $long_line = File::Spec->catfile($temporary, "long-line.rules");
write_bytes($long_line, scalar("#" x (MAX_RULE_LINE_BYTES() + 1)));
eval { read_bounded_rules($long_line, 0) };
my $long_line_error = $@;
like($long_line_error, qr/Rule line exceeds 4096 bytes/, "individual rule lines are bounded");

my $crowded = File::Spec->catdir($temporary, "crowded");
make_path($crowded);
for my $index (0 .. 256) {
  write_bytes(File::Spec->catfile($crowded, sprintf("p-%03d", $index)), "");
}
eval { read_profiles($crowded) };
like($@, qr/exceeds 256 entries/, "profile directory entry count is bounded");

my $encoded = encode_bounded_payload({
  ok   => JSON::PP::true,
  data => "x" x (MAX_OUTPUT_BYTES() + 1),
});
my $decoded = JSON::PP->new->utf8->decode($encoded);
ok(!$decoded->{ok}, "producer replaces oversized JSON with a bounded error");
ok(length($encoded) <= MAX_OUTPUT_BYTES(), "producer output stays within its cap");

done_testing;
