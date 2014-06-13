#!/usr/bin/perl

# Name: testmemcache.pl
# Author: Walter Cinquanta Jr
# Description: Script to check key/value pair addition and removal (w/ delay)
# Notes: none
# TODO: Install Cache::Memcached perl api module


use strict;
use Cache::Memcached;

my $md = new Cache::Memcached {
	servers => [ "127.0.0.1:11211" ],
	debug => 1,
	compress_threshold => 10_000,
};

$md->set("test_key", "works");

my $tk = $md->get("test_key");

print "test key/value pair: $tk\n";

$md->delete("test_key", 5);

my $tk_alive = $md->get("test_key");

if ($tk_alive) {
	print "PASSED: testkey alive check: $tk_alive\n";
} else {
	print "FAILED: testkey alive check: key vanished before time delete delay\n";
}

sleep 6;

my $tk_dead = $md->get("test_key");

if ($tk_dead) {
	print "PASSED: testkey dead check: '$tk_dead'\n";
} else {
	print "FAILED: testkey dead check: '$tk_dead' - key did not vanish in 5 seconds\n";
}
