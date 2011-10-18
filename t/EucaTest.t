# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl EucaTest.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 1;
BEGIN { use_ok('EucaTest') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

#"root:foobar\@192.168.51.74"
my $euca = EucaTest->new({host=>"local"});
 
like($euca->get_fail_count(), qr/0/, "Check for default eucadir");

