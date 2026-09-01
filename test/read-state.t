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
