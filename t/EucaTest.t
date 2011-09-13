# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl EucaTest.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 3;
BEGIN { use_ok('EucaTest') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

#"root:foobar\@192.168.51.74"
my $euca = EucaTest->new();
 
my @output = $euca->sys("whoami");

like($output[0], qr/^/, "Check simple whoami command on remote device");
diag("Output is: @output");
my $mycredpath = "yada";
$euca->set_credpath($mycredpath);
my $new_credpath = $euca->get_credpath();
like($new_credpath, qr/$mycredpath/, "Check for default credpath");
diag("Credpath set to  $new_credpath");