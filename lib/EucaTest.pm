package EucaTest;

use 5.000003;
use strict;
use warnings;

use Net::OpenSSH;
require Exporter;
use Data::Dumper;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
# This allows declaration	use EucaTest ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = (
	'all' => [
		qw( test_name fail pass

		  )
	]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

our $VERSION = '0.01';
our $ofile   = "ubero";
my $CLC_INFO = {};
my @running_log;

# timeouts
my $INST_AVAILABLE_TIMEOUT_SEC = 20;
my $INST_IP_TIMEOUT_SEC        = 20;

open( STDERR, ">&STDOUT" );

##################

##################

sub new {
	my $ssh;
	my $class      = shift;
	my $opts       = shift;
	my $host       = $opts->{'host'};
	my $keypath    = $opts->{'keypath'};
	my $fail_count = 0;

	my $credpath = $opts->{'credpath'};
	if ( !defined $credpath ) {
		$credpath = "";
	}
	my $delay = $opts->{'delay'};
	if ( !defined $delay ) {
		$delay = 1;
	}

	my $timeout = $opts->{'timeout'};
	if ( !defined $timeout ) {
		$timeout = 120;
	}

	my $eucadir = $opts->{'eucadir'};
	if ( !defined $eucadir ) {
		$eucadir = "/opt/eucalyptus";
	}

	my $verify_level = $opts->{'verifylevel'};
	if ( !defined $verify_level ) {
		$verify_level = "10";
	}

	my $toolkit = $opts->{'toolkit'};
	if ( !defined $toolkit ) {
		$toolkit = "euca-";
	}
	my $input_file = $opts->{'input_file'};
	if ( !defined $input_file ) {
		$input_file = "../input/2b_tested.lst";
	}

	## Need to add colon to hostname after user if sending a password embedded in the hostname OpenSSH requirement
	my $password = $opts->{'password'};
	if ( !defined $password ) {
		$password = "";
	} else {
		$password = ":" . $password;
	}
	my $self = { SSH => $ssh, CREDPATH => $credpath, TIMEOUT => $timeout, EUCADIR => $eucadir, VERIFY_LEVEL => $verify_level, TOOLKIT => $toolkit, DELAY => $delay, FAIL_COUNT => $fail_count, INPUT_FILE => $input_file, PASSWORD => $password };
	bless $self;

	$CLC_INFO = $self->read_input_file($input_file);
	if ( !defined $host ) {
		$host = "root" . $password . "\@" . $CLC_INFO->{'QA_IP'};
	}
	### IF we are going to a remote server to exec commands
	if ( $host !~ /local/i ) {
		chomp $host;
		print "Creating an SSH connection to $host\n";
		## are we authenticating with keys or with password alone
		if ( defined $keypath ) {
			chomp $keypath;

			#			 $self->test_name("Creating a keypair authenticated SSH connection to $host");
			$ssh = Net::OpenSSH->new( $host, key_path => $keypath, master_opts => [ -o => "StrictHostKeyChecking=no" ] );
			$self->{SSH} = $ssh;
			print $ssh->error;

		} else {

			#			$self->test_name( "Creating a password authenticated SSH connection to $host");
			$ssh = Net::OpenSSH->new( $host, master_opts => [ -o => "StrictHostKeyChecking=no" ] );
			$self->{SSH} = $ssh;
			print $ssh->error;
		}
	} else {
		print "Creating a LOCAL connection\n";
		undef $ssh;
	}

	### IF we dont have credentials and are sshing to a remote host, get credentials
	if ( defined $ssh && $self->get_credpath eq "" ) {
		my $admin_credpath = $self->get_cred( "eucalyptus", "admin" );
		if ( $admin_credpath !~ /eucarc/ ) {
			$self->fail("Failed to download credentials");
		} else {
			$self->set_credpath($admin_credpath);
		}

	}
	if ( defined $CLC_INFO->{'QA_SOURCE'} && $CLC_INFO->{'QA_SOURCE'} =~ /repo/i ) {
		$self->set_eucadir("/");
	}

	return $self;
}

sub fail {
	my $self    = shift;
	my $message = shift;

	push( @running_log, "^^^^^^[TEST_REPORT] FAILED $message^^^^^^\n" );
	print("^^^^^^[TEST_REPORT] FAILED $message^^^^^^\n");
	$self->{FAIL_COUNT}++;

	return 0;
}

# Print formatted success message
sub pass {
	my $self    = shift;
	my $message = shift;

	push( @running_log, "^^^^^^[TEST_REPORT] PASSED - $message^^^^^^\n\n" );
	print("^^^^^^[TEST_REPORT] PASSED - $message^^^^^^\n\n");

	return 0;
}

# Print test case name (ie a description of the following steps)
sub test_name {
	my $self = shift;
	my $name = shift;

	push( @running_log, "******[TEST_REPORT] ACTION - $name ******\n" );
	print("******[TEST_REPORT] ACTION - $name ******\n");
}

sub log {
	my $self    = shift;
	my $message = shift;
	push( @running_log, "$message" );
	return 0;
}

sub tee {
	my $self    = shift;
	my $message = shift;
	$self->log("$message");
	print($message);
	return 0;
}

sub generate_random_string {
	my $self  = shift;
	my $len   = shift;
	my @chars = ( 'a' .. 'z', 'A' .. 'Z', '0' .. '9', '-' );
	my $string;
	foreach ( 1 .. $len ) {
		$string .= $chars[ rand @chars ];
	}
	return $string;
}

sub get_fail_count {
	my $self = shift;
	return $self->{FAIL_COUNT};
}

sub get_verifylevel {
	my $self = shift;
	return $self->{VERIFYLEVEL};
}

sub set_verifylevel {
	my $self  = shift;
	my $level = shift;
	$self->{VERIFYLEVEL} = $level;
	return 0;
}

sub get_delay {
	my $self = shift;
	return $self->{DELAY};
}

sub set_delay {
	my $self  = shift;
	my $delay = shift;
	$self->{DELAY} = $delay;
	return 0;
}

sub get_toolkit {
	my $self = shift;
	return $self->{TOOLKIT};
}

sub set_toolkit {
	my $self    = shift;
	my $toolkit = shift;
	$self->{TOOLKIT} = $toolkit;
	return 0;
}

sub get_ssh {
	my $self = shift;
	return $self->{SSH};
}

sub set_ssh {
	my $self = shift;
	my $ssh  = shift;
	$self->{SSH} = $ssh;
	return 0;
}

sub get_eucadir {
	my $self = shift;
	return $self->{EUCADIR};
}

sub set_eucadir {
	my $self = shift;
	my $dir  = shift;
	$self->{EUCADIR} = $dir;
	return 0;
}

sub get_timeout {
	my $self = shift;
	return $self->{TIMEOUT};
}

sub set_timeout {
	my $self    = shift;
	my $timeout = shift;
	$self->{TIMEOUT} = $timeout;
	return 0;
}

sub get_credpath {
	my $self = shift;
	return $self->{CREDPATH};
}

sub set_credpath {
	my $self     = shift;
	my $credpath = shift;
	$self->sys("cat $credpath/eucarc  | grep -v EUCA_KEY_DIR= > $credpath/eucarc.tmp");
	$self->sys("echo EUCA_KEY_DIR=$credpath > $credpath/eucarc.dir; cat $credpath/eucarc.tmp >> $credpath/eucarc.dir; mv $credpath/eucarc.dir $credpath/eucarc");

	$self->{CREDPATH} = $credpath;

	return 0;
}

sub download_keypair {
	my $self    = shift;
	my $keypair = shift;
	my @rsa_pub = `cat ~/.ssh/id_rsa.pub`;
	$self->sys("echo \'@rsa_pub\' >> ~/.ssh/authorized_keys");
	my $cmd          = "scp root\@$CLC_INFO->{'QA_IP'}:$keypair.priv .";
	my $keypair_text = `$cmd`;
	return $keypair;

}

sub cleanup {
	my $self     = shift;
	my $tc_id    = shift;
	my $tplan_id = shift;
	if ( defined $tc_id && defined $tplan_id ) {

		$self->update_testlink( $tc_id, $tplan_id );
	}
	$self->sys("rm -f *.priv *.log");
	$self->sys("rm -rf $self->{CREDPATH}");
	my @rm_log = `rm *.log`;
	return 0;
}

sub clear_log {
	my $self = shift;
	@running_log = ();
}

sub update_testlink {
	my $self     = shift;
	my $tc_id    = shift;
	my $tplan_id = shift;
	my $status   = shift;
	my $build    = shift;

	### Get status from total fail_count
	if ( !defined $status ) {
		$status = 'f';
		if ( $self->get_fail_count() == 0 ) {
			$status = "p";
		}
	}

	my $notes    = "";
	my $platform = 1;

	if ( defined $CLC_INFO->{"QA_DISTRO"} ) {
		my $qa_distro     = $CLC_INFO->{"QA_DISTRO"};
		my $qa_distro_ver = $CLC_INFO->{'QA_DISTRO_VER'};
		my $qa_arch       = $CLC_INFO->{'QA_ARCH'};
		my $qa_source     = $CLC_INFO->{'QA_SOURCE'};
		my $qa_roll       = $CLC_INFO->{'QA_ROLL'};
		my $qa_ip         = $CLC_INFO->{'QA_IP'};

		#[ID: 1 ] CentOS 5 64bit
		#[ID: 2 ] CentOS 5 32bit
		#[ID: 3 ] RHEL 5 32bit
		#[ID: 4 ] Ubuntu Lucid 64bit
		#[ID: 5 ] Ubuntu Lucid 32bit
		#[ID: 7 ] RHEL 5 64bit
		#[ID: 8 ] Debian Squeeze 64bit
		if ( !defined $CLC_INFO->{'NODE_DISTRO'} ) {
			$CLC_INFO->{'NODE_DISTRO'} = "unknown";
		}
		if ( $CLC_INFO->{'NODE_DISTRO'} =~ /VMWARE/i ) {
			if ( $qa_distro =~ /CENTOS/i ) {
				$platform = 12;
			} elsif ( $qa_distro =~ /UBUNTU/i ) {
				$platform = 11;
			}
		} elsif ( ( $qa_distro =~ /CENTOS/i ) && ( $qa_arch =~ /64/ ) ) {
			$platform = 1;
		} elsif ( ( $qa_distro =~ /CENTOS/i ) && ( $qa_arch =~ /32/ ) ) {
			$platform = 2;
		} elsif ( ( $qa_distro =~ /RHEL/i ) && ( $qa_arch =~ /64/ ) ) {
			$platform = 7;
		} elsif ( ( $qa_distro =~ /RHEL/i ) && ( $qa_arch =~ /32/ ) ) {
			$platform = 3;
		} elsif ( ( $qa_distro =~ /UBUNTU/i ) && ( $qa_arch =~ /64/ ) ) {
			$platform = 4;
		} elsif ( ( $qa_distro =~ /UBUNTU/i ) && ( $qa_arch =~ /32/ ) ) {
			$platform = 5;
		} elsif ( ( $qa_distro_ver =~ /DEBIAN/i ) && ( $qa_arch =~ /64/ ) ) {
			$platform = 8;
		}

		#push(@running_log, "IP $qa_ip [Distro $qa_distro, Version $qa_distro_ver, ARCH $qa_arch] is built from $qa_source as Eucalyptus-$qa_roll\n");

	}
	### Add the entire config file to the top of the result
	if ( defined $CLC_INFO->{"TEST_NAME"} ) {
		my $artifacts_link = "http://10.1.1.210/test_space/" . $CLC_INFO->{"TEST_NAME"} . "/" . $CLC_INFO->{"UNIQUE_ID"};
		$artifacts_link = "<a href=\"" . $artifacts_link . "\" style=\"color:blue;font-size:20px;\" target=\"_blank\">Go to Artifacts</a> ";
		$CLC_INFO->{"INPUT_FILE"} = $artifacts_link . "<br>" . $CLC_INFO->{"INPUT_FILE"};
		$CLC_INFO->{"INPUT_FILE"} =~ s/\n/<br>/g;

	}
	$CLC_INFO->{"INPUT_FILE"} = "##################### TEST SETUP #####################\n" . $CLC_INFO->{"INPUT_FILE"} . "\n\n\n##################### TEST OUTPUT #####################\n";

	### DETERMINE TEST STATUS
	### Remove \n and replace with HTML newline character <br>

	foreach my $line (@running_log) {
		if ( $line =~ /\[.*TEST_REPORT.*].*failed/i ) {

			#if($line =~ /fail/i){
			$status = 'f';
			$line   = "<font color=\"red\" size=\"4\">$line</font>";
		} elsif ( $line =~ /\[.*].*/ ) {
			$line = "<font color=\"blue\" size=\"2\">$line</font>";
		}

		$line =~ s/\n/<br>/g;

	}
	unshift( @running_log, $CLC_INFO->{"INPUT_FILE"} );
	##
	### CHECK FOR test.fail file in status directory
	my $filename = "../status/test.failed";
	if ( -e $filename ) {
		$status = 'f';
		open FAIL, "<$filename" or die $!;
		my @fail_file = <FAIL>;
		close(FAIL);
		unshift( @running_log, "<font color=\"red\" size=\"4\">@fail_file</font><br>" );
	}
	chomp($tc_id);
	my $run_file = "run-$tc_id-" . time() . ".log";
	open FILE, ">", "$run_file" or die $!;
	print FILE"@running_log";
	close FILE;
	my @scp_result = `scp $run_file root\@192.168.51.187:artifacts/$run_file`;

	#print "@scp_result";

	### IF a different testplan is in the memo update that one
	### else if the branch is not eee then put it into the NON-EEE testplan
	my @branch_url = split( /\//, $CLC_INFO->{'BZR_BRANCH'} );
	my $branch_name = @branch_url[ @branch_url - 1 ];
	if ( defined $CLC_INFO->{"TESTPLAN_ID"} ) {
		$tplan_id = $CLC_INFO->{"TESTPLAN_ID"};
		$tplan_id =~ s/[^\w\d]//g;
	} elsif ( $CLC_INFO->{"TEST_NAME"} !~ /GA-/ ) {
		### THIS MAPS TO THE NON-EEE TESTPLAN IN TESTLINK
		$tplan_id = 380;
	}

	### DECIDE WHAT TO CALL THE BUILD
	$build = "other";

	### MAKE SURE I HAVE A REVNO OF SOME SORT
	if ( defined $CLC_INFO->{'BZR_REVISION'} ) {

		## IF THIS IS A GA TRIGGERED TEST
		if ( $CLC_INFO->{"TEST_NAME"} =~ /GA-/i ) {
			### IF THIS IS FROM REPO MAKE IT REPO
			if ( $CLC_INFO->{'QA_SOURCE'} =~ /repo/i ) {
				$build = "$branch_name GA REPO";
			} else {
				$build = "$branch_name GA SRC " . $CLC_INFO->{'BZR_REVISION'};
			}

		}
		### OTHERWISE THIS IS A NON TRIGGERED TEST SO JUST CALL IT BY ITS BRANCH NAME and REVNO
		else {
			if ( $CLC_INFO->{'QA_SOURCE'} =~ /repo/i ) {
				$build = "$branch_name REPO " . $CLC_INFO->{'BZR_REVISION'};
			} else {
				$build = "$branch_name SRC " . $CLC_INFO->{'BZR_REVISION'};
			}

		}
	} else {
		print "No REVNO found so not updating testlink, talk to Vic";
		return undef;
	}

	chomp($tplan_id);

	#################################
	my @mkdir_artifacts_response = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'mkdir artifacts\'");
	my @build_response           = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'./testlink/update_build.pl testplanid=$tplan_id \"$build\"'");
	my $build_id                 = $build_response[0];
	chomp($build_id);
	my @exec_resp = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'./testlink/update_testcase.pl artifacts/$run_file testcaseexternalid=$tc_id,testplanid=$tplan_id,status=$status,buildid=$build_id,platformid=$platform\'");
	if ( @exec_resp < 1 ) {
		print "Could not update testcase in testplan";
		return undef;
	}
	my @rm_resp = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'rm artifacts/$run_file \'");
	##UPLOADING THE TC RESULT WILL RETURN ME THE EXEC ID

	$self->sys("rm $run_file");
	print "Updated Testcase: $tc_id in Testplan $tplan_id with result $status on build $build_id which is revno $build and exec_id \n";
	return $exec_resp[0];
}

sub attach_artifacts {
	my $self    = shift;
	my $exec_id = shift;
	if ( !defined $exec_id || $exec_id == -1 ) {
		print "Invalid exec_id provided to attach artifacts\n";
		return undef;
	}
	chomp $exec_id;
	## SEND THE ARTIFACTS TO THE REMOTE MACHINE
	my @mkdir_artifacts_response = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'mkdir artifacts\'");
	my @mkdir_execid_response    = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'mkdir artifacts/$exec_id\'");
	my @scp_artifacts_result     = `scp ../artifacts/*.out root\@192.168.51.187:artifacts/$exec_id`;

	## LOOK FOR ALL THE REMOTE ARTIFACTS UPLOADED
	my @remote_artifacts = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'ls artifacts/$exec_id\'");

	foreach my $artifact (@remote_artifacts) {
		chomp $artifact;
		### SKIP IF ITS NOT A RUN SCRIPT
		if ( $artifact =~ /run-script/ ) {
			my @exec_resp = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'./testlink/upload_attachment.pl artifacts/$exec_id/$artifact filename=$artifact,filetype=text/html,executionid=$exec_id\'");
		}
	}

	##DELETE ARTICACTS AFTER UPLOAD
	my @remove_artifacts = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'rm -rf artifacts/$exec_id\'");
	return 0;
}

sub set_clc_info {
	my $self = shift;
	$CLC_INFO = shift;
	return 0;
}

sub timestamp {
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
	my $timestamp = sprintf( "%02d-%02d %02d:%02d:%02d\n", $mon + 1, $mday, $hour, $min, $sec );
	chomp($timestamp);
	return $timestamp;
}

sub sys {
	my $self         = shift;
	my $cmd          = shift;
	my $timeout      = shift;
	my $original_cmd = $cmd;
	if ( $self->{CREDPATH} ne "" ) {
		$cmd = ". " . $self->{CREDPATH} . "/eucarc && " . $cmd;
	}

	sleep( $self->{DELAY} );
	my $systimeout;
	if ( defined $timeout ) {
		$systimeout = $timeout;
	} else {
		$systimeout = $self->{TIMEOUT};
	}

	my @output;

	# Return and print failure
	$SIG{ALRM} = sub { die "alarm\n"; };
	eval {
		alarm($systimeout);

		my $timestamp = timestamp();

		if ( defined $self->{SSH} ) {
			my $rem_host = $self->{SSH}->get_host();
			my $rem_user = $self->{SSH}->get_user();
			$self->tee("[$rem_user\@$rem_host - $timestamp] $original_cmd\n");
			@output = $self->{SSH}->capture($cmd);

			#$self->{SSH}->error and $self->fail( "SSH ERROR: " . $self->{SSH}->error);

		} else {

			$self->tee("[LOCAL - $timestamp] $original_cmd\n");
			@output = `$cmd`;

		}
		alarm(0);

	};
	if ($@) {
		die unless $@ eq "alarm\n";    # propagate unexpected errors
		                               # timed out
		$self->tee("@output\n");
		$self->fail("Timeout occured after $systimeout seconds\n");

		return @output;
	} else {                           # didn't
		$self->tee("@output\n");
		return @output;

	}

}

sub read_input_file {
	my $self     = shift;
	my $filename = shift;
	my $is_memo  = 0;
	my $memo     = "";
	my %CONFIG;
	open( INPUT, "< $filename" ) || die $!;

	my $line;
	while ( $line = <INPUT> ) {
		$CONFIG{'INPUT_FILE'} .= $line;
		chomp($line);
		if ($is_memo) {
			if ( $line ne "END_MEMO" ) {

				###LOOK FOR THE TESTPLAN_ID IN THE MEMO
				if ( $line =~ /^TESTPLAN_ID/ ) {
					my @testplan_id = split( /=/, $line );
					$testplan_id[1] =~ s/[^\w\d]//g;
					$CONFIG{'TESTPLAN_ID'} = $testplan_id[1];
				}

				### ADD THIS LINE TO THE MEMO
				$memo .= $line . "\n";
			}
		}
		if ( $line =~ /^BZR_REVISION/ ) {
			my @bzr_rev = split( /\s+/, $line );
			$CONFIG{'BZR_REVISION'} = $bzr_rev[1];
		}
		if ( $line =~ /^TEST_NAME/ ) {
			my @test_name = split( /\s+/, $line );
			$CONFIG{'TEST_NAME'} = $test_name[1];
		}
		if ( $line =~ /^UNIQUE_ID/ ) {
			my @unique_id = split( /\s+/, $line );
			$CONFIG{'UNIQUE_ID'} = $unique_id[1];
		}
		if ( $line =~ /^NETWORK/ ) {
			my @network = split( /\s+/, $line );
			$CONFIG{'NETWORK'} = $network[1];
		}
		if ( $line =~ /^BZR_BRANCH/ ) {
			my @bzr_branch = split( /\s+/, $line );
			$CONFIG{'BZR_BRANCH'} = $bzr_branch[1];
		}

		if ( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ) {
			my $qa_ip         = $1;
			my $qa_distro     = $2;
			my $qa_distro_ver = $3;
			my $qa_arch       = $4;
			my $qa_source     = $5;
			my $qa_roll       = $6;

			my $this_roll = lc($6);
			if ( $this_roll =~ /clc/ ) {
				print "\n";
				$CONFIG{'QA_DISTRO'}     = $qa_distro;
				$CONFIG{'QA_DISTRO_VER'} = $qa_distro_ver;
				$CONFIG{'QA_ARCH'}       = $qa_arch;
				$CONFIG{'QA_SOURCE'}     = $qa_source;
				$CONFIG{'QA_ROLL'}       = $qa_roll;
				$CONFIG{'QA_IP'}         = $qa_ip;
				print "IP $qa_ip [CLC Distro: $qa_distro CLC Version: $qa_distro_ver CLC ARCH $qa_arch] is built from $qa_source as Eucalyptus-$qa_roll\n";
			} elsif ( $this_roll =~ /nc/ ) {

				$CONFIG{'NODE_DISTRO'}     = $qa_distro;
				$CONFIG{'NODE_DISTRO_VER'} = $qa_distro_ver;
				print "IP $qa_ip [NC Distro: $qa_distro NC Version: $qa_distro_ver NC ARCH $qa_arch] is built from $qa_source as Eucalyptus-$qa_roll\n";
			}

		} elsif ( $line =~ /^MEMO/ ) {
			$is_memo = 1;
		} elsif ( $line =~ /^END_MEMO/ ) {
			$is_memo = 0;
		}
	}
	if ( $CONFIG{'QA_SOURCE'} =~ /repo/i ) {
		$self->{EUCADIR} = "/";
	}

	close(INPUT);

	$CONFIG{'QA_MEMO'} = $memo;

	$CLC_INFO = \%CONFIG;

	return \%CONFIG;
}

sub piperun {
	my $self      = shift;
	my $cmd       = shift @_;
	my $pipe      = shift @_;
	my $uberofile = shift @_ || "/tmp/uberofile.$$";
	my $pipestr   = "";

	if ($pipe) {
		$pipestr = "| $pipe";
	}

	my @buf     = $self->sys("$cmd > /tmp/tout.$$ 2>&1");
	my $retcode = ${^CHILD_ERROR_NATIVE};

	chomp( my $buf = `cat /tmp/tout.$$ $pipestr` );
	my $pipecode = system("cat /tmp/tout.$$ $pipestr >/dev/null 2>&1");

	system("echo '*****' >> $uberofile");
	system("echo CMD=$cmd >> $uberofile");
	my $rc = system("cat /tmp/tout.$$ >> $uberofile");
	unlink("/tmp/tout.$$");

	sleep(1);
	return ( $retcode, $pipecode, $buf );
}

sub get_cred {
	my ( $self, $account, $user, $cred_dir ) = @_;
	if ( !defined $cred_dir ) {
		$cred_dir = "eucarc-$account-$user";
	}
	$self->sys( "rm -rf " . $cred_dir );
	$self->sys( "mkdir " . $cred_dir );

	if ( !$self->found( "ls", qr/$cred_dir/ ) ) {
		$self->fail("Unable to make directory: $cred_dir");
		return "";
	}

	my $cmd = $self->{EUCADIR} . "/usr/sbin/euca_conf --get-credentials $cred_dir/euca.zip --cred-account $account --cred-user $user";
	##Get credentials as a zip file in $cred_dir
	$self->sys($cmd);

	if ( !$self->found( "ls $cred_dir", qr/euca.zip/ ) ) {
		$self->fail("Unable to make credentials");
		return "";
	}

	##Change to that directory and unzip the credentials
	$self->sys("cd $cred_dir; unzip -o euca.zip");

	return "$cred_dir";
}

### UNDOCUMENTED API
sub download_cred {
	my $self       = shift;
	my $create_dir = `mkdir $self->{CREDPATH}`;
	print $create_dir;
	$self->{SSH}->scp_get( { glob => 1 }, $self->{CREDPATH} . "/*", "$self->{CREDPATH}" );
	return $self->{CREDPATH};
}

## UNDOCUMENTED API
sub send_cred {
	my $self = shift;
	my $host = shift;
	$self->sys("scp -r $self->{CREDPATH} $host");
	return $self->{CREDPATH};
}

sub add_keypair {
	my $self     = shift;
	my $keyname  = shift;
	my $filepath = "$keyname.priv";
	$self->sys("$self->{TOOLKIT}add-keypair $keyname | grep -v KEYPAIR > $filepath");
	sleep 1;

	#If the private key file exists and the first line starts with BEGIN RSA PRIVATE KEY
	my @lsresult = $self->sys("ls $filepath");

	if ( $lsresult[0] !~ m/cannot access/ ) {

		my @KEYFILE = $self->sys("cat $filepath");
		if ( $KEYFILE[0] =~ /BEGIN RSA PRIVATE KEY/ ) {
			$self->pass("Correctly added keypair $keyname");
			$self->sys("chmod 0600 $filepath");
			return $keyname;
		} else {
			$self->fail("No key inside private key file");
			my @key = $self->sys("cat $filepath");
			print "Key File Contains:\n@key";
			return undef;
		}
	} else {
		$self->fail("Keypair file not found at $filepath");
		return undef;
	}

}

sub delete_keypair {
	my $self     = shift;
	my $keyname  = shift;
	my $filepath = "$keyname.priv";
	my @output   = $self->sys("$self->{TOOLKIT}delete-keypair $keyname");

	if ( @output < 1 ) {
		$self->fail("Delete keypair command did not return anything");
		return undef;
	}
	## Check the first line of output for KEYPAIR
	if ( $output[0] =~ /KEYPAIR/ ) {

		### THIS will falsely detect keypairs that contain the $keyname #################3
		#my @output = $self->sys("euca-describe-keypairs | grep $keyname");
		#ENSURE THE KEYPAIR NO LONGER EXISTS

		if ( !$self->found( "$self->{TOOLKIT}describe-keypairs", qr/$keyname/ ) ) {
			$self->pass("Deleted keypair $keyname");
			$self->sys("rm -f $filepath");
			return $keyname;
		} else {
			$self->fail("Keypair is still present or a keypair with this keypairs name embedded exists");
			return undef;
		}

	} else {
		$self->fail("Delete keypair command did not return the keypair which was deleted");
		return undef;
	}
}

sub get_keypair {
	my $self     = shift;
	my $keyname  = shift;
	my $filepath = "$keyname.priv";
	my @key      = $self->sys("cat $filepath");
	return "@key";
}

sub found {
	my ( $self, $list_cmd, $to_search ) = @_;
	my $found = 0;
	for my $item ( $self->sys($list_cmd) ) {
		if ( $item =~ /$to_search/ ) {
			$found = 1;
			return $found;
		}
	}
	return $found;
}

sub add_group {
	my $self      = shift;
	my $groupname = shift;
	my $rule      = shift;

	### CHECK IF THE GROUP EXISTS
	my @desc_groups = $self->sys("$self->{TOOLKIT}describe-groups $groupname");

	### IF IT DOES NOT EXIST CREATE IT
	if ( @desc_groups < 1 ) {
		my @add_group = $self->sys("$self->{TOOLKIT}add-group $groupname -d $groupname");
		if ( $add_group[0] =~ /GROUP/ ) {
			$self->pass("Added group $groupname successfully");
		} else {
			$self->fail("Unable to add group $groupname");
			return undef;
		}
	} else {
		$self->pass("Group $groupname already exists not creating");
	}

	### IF THE USER DOES NOT PROVIDE A RULE CREATE THE GROUP with p22 and icmp
	if ( !defined $rule ) {

		my @auth_icmp = $self->sys("$self->{TOOLKIT}authorize $groupname -P icmp");
		if ( $auth_icmp[0] =~ /GROUP/ ) {
			$self->pass("Added ICMP authorization for $groupname successfully");
		} else {
			$self->fail("Unable authorize group $groupname for ICMP");
			return undef;
		}

		my @auth_ssh = $self->sys("$self->{TOOLKIT}authorize $groupname -p 22");
		if ( $auth_ssh[0] =~ /GROUP/ ) {
			$self->pass("Added SSH authorization for $groupname successfully");
		} else {
			$self->fail("Unable authorize group $groupname for SSH");
			return undef;
		}
	} else {
		my @auth_rule = $self->sys("$self->{TOOLKIT}authorize $groupname $rule");
		if ( $auth_rule[0] =~ /GROUP/ ) {
			$self->pass("Added $rule authorization for $groupname successfully");
		} else {
			$self->fail("Unable authorize group $groupname for $rule");
			return undef;
		}
	}

	return ($groupname);
}

sub delete_group {
	my $self      = shift;
	my $groupname = shift;
	my $ip        = shift;
	my @add_group = $self->sys("$self->{TOOLKIT}delete-group $groupname");
	if ( $add_group[0] =~ /GROUP/ ) {
		$self->pass("Deleted group $groupname successfully");
		return $groupname;
	} else {
		$self->fail("Unable to delete group $groupname");
		return undef;
	}
}

sub allocate_address {
	my $self   = shift;
	my @output = $self->sys("$self->{TOOLKIT}allocate-address");
	if ( $output[0] =~ /ADDRESS/ ) {
		my @ip = split( ' ', $output[0] );
		$self->pass("Address $ip[1] allocated");
		return $ip[1];
	} else {
		$self->fail("Unable to allocate address");
		return undef;
	}

}

sub release_address {
	my $self    = shift;
	my $address = shift;

	my @output = $self->sys("$self->{TOOLKIT}release-address $address");
	if ( $output[0] =~ /ADDRESS/ ) {
		my @ip = split( ' ', $output[0] );
		if ( $ip[1] =~ $address ) {
			$self->pass("Address $ip[1] released");
			return $ip[1];
		} else {
			$self->fail("Wrong address released");
			return undef;
		}
	} else {
		$self->fail("Unable to release address $address");
		return undef;
	}
}

sub get_emi {
	my $self   = shift;
	my $filter = shift;
	my $cmd    = "$self->{TOOLKIT}describe-images | grep -v windows | grep available | grep emi";
	if ( defined $filter ) {
		$cmd .= " | grep $filter";
	}
	my @output = $self->sys($cmd);
	if ( @output < 1 ) {
		$self->fail("No EMI found");
		return undef;
	}
	if ( $output[0] =~ /emi/ ) {
		my @emi = split( ' ', $output[0] );
		$self->pass("Found EMI $emi[1]");
		return $emi[1];
	} else {
		$self->fail("No EMIs found");
		return undef;
	}

}

### A machine is a hash of: distro, ip, distro_ver, roles (array), arch, qa_source
###@machines =  get_machines(clc)

sub get_machines {
	my $self    = shift;
	my $role    = shift;
	my $is_memo = 0;
	my $memo    = "";
	my @machines;

	open( INPUT, "< ../input/2b_tested.lst" ) || die $!;
	my $line;

	while ( $line = <INPUT> ) {
		chomp($line);
		### IF THIS IS FORMATTED THE WAY THE QA INPUT FILE NEEDS TO SEE MACHINES
		if ( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ) {
			### PARSE THE REGEX and get identified values
			my $current_machine = {};
			$current_machine->{'ip'}         = $1;
			$current_machine->{'distro'}     = $2;
			$current_machine->{'distro_ver'} = $3;
			$current_machine->{'arch'}       = $4;
			$current_machine->{'source'}     = $5;
			$current_machine->{'role'}       = $6;

			#my @roles = split(/\s+/, $qa_role);
			#= @roles;
			if ( !defined $role || $current_machine->{'role'} =~ /$role/i ) {
				push( @machines, $current_machine );
			}
		}
	}

	close(INPUT);

	return @machines;
}

### returns an ARRAY [indexed by cluster] of HASHES {keyed on component abbrv} of  ARRAYS [indexed on component number] of MACHINES
### @clusters = get_clusters();
### $cluster[0]->{'cc'}[0]->{'ip'}
### $cluster[0]->{'cc'}[1]->{'distro'}
sub get_clusters {
	my $self = shift;
	my @clusters;
	open( INPUT, "< ../input/2b_tested.lst" ) || die $!;
	my $line;

	while ( $line = <INPUT> ) {
		chomp($line);

		### IF THIS IS FORMATTED THE WAY THE QA INPUT FILE NEEDS TO SEE MACHINES
		if ( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ) {
			my $current_machine = {};
			$current_machine->{'ip'}         = $1;
			$current_machine->{'distro'}     = $2;
			$current_machine->{'distro_ver'} = $3;
			$current_machine->{'arch'}       = $4;
			$current_machine->{'source'}     = $5;
			$current_machine->{'role'}       = $6;

		}
	}
	return @clusters;
}

sub discover_emis {
	my $self = shift;

	my $cmd = "$self->{TOOLKIT}describe-images";
	my ( $crc, $rc, $buf ) = piperun( $cmd, "grep IMAGE | grep -i 'mi-' | grep available | awk '{print \$2}'", "$ofile" );
	if ($rc) {
		$self->fail("Failed in running describe images when trying to discover EMIs");
		return undef;
	}
	my @emi_list = ();
	my @output = split( /\s+/, $buf );
	foreach my $emi (@output) {
		if ( !$emi || $emi eq "" || !( $emi =~ /.*mi-.*/ ) ) {
			print "WARN: emis=@output, emi=$emi\n";
		} else {
			push( @emi_list, $emi );
		}
	}

	return @emi_list;
}

### TAKES in the url to a euca packaged image
sub download_euca_image {
	my $self   = shift;
	my $source = shift;
	my $dest   = shift;

	#Download the tarball
	if ( !defined $source || !defined $dest ) {
		$self->fail("Base URL or image name not defined");
		return undef;
	}
	$self->sys( "wget $source$dest", 600 );
	if ( !$self->found( "ls", qr/$dest/ ) ) {
		$self->fail("Unable to download file");
		return undef;
	} else {
		print "Finished downloading file: $dest\n";
	}

	## Untar the bundle
	$self->sys("tar xzf $dest");
	my @dir = split( /.tgz/, $dest );
	if ( !$self->found( "ls $dir[0]", qr/.img/ ) ) {
		$self->fail("Unable to untar file");
		return undef;
	} else {
		print "Finished untarring bundle: $dest\n";
	}

	return $dir[0];
}

sub upload_euca_image {
	my $self       = shift;
	my $dir        = shift;
	my $hypervisor = shift;
	my $prefix     = shift;
	if ( !defined $dir || !defined $hypervisor || !defined $prefix ) {
		$self->fail("Required params for upload_euca_image not defined");
		return undef;
	}

	$self->set_timeout(600);

	my @kernel  = $self->sys("ls -m1 $dir/$hypervisor-kernel/vmlinuz* | xargs -n1 basename");
	my @ramdisk = $self->sys("ls -m1 $dir/$hypervisor-kernel/initrd* | xargs -n1 basename");
	my @image   = $self->sys("ls -m1 $dir/*.img | xargs -n1 basename");
	chomp(@kernel);
	chomp(@ramdisk);
	chomp(@image);

	#$self->sys("mkdir bundle");
	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$hypervisor-kernel/$kernel[0] -d bundle --kernel true");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-kernel-bucket -m bundle/$kernel[0].manifest.xml");
	my @eki_result = $self->sys("$self->{TOOLKIT}register $prefix-kernel-bucket/$kernel[0].manifest.xml");
	if ( $eki_result[0] !~ /eki/ ) {
		$self->fail("Kernel not uploaded properly: $eki_result[0]");
		return undef;
	}

	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$hypervisor-kernel/$ramdisk[0] -d bundle --ramdisk true");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-ramdisk-bucket -m bundle/$ramdisk[0].manifest.xml");
	my @eri_result = $self->sys("$self->{TOOLKIT}register $prefix-ramdisk-bucket/$ramdisk[0].manifest.xml");
	if ( $eri_result[0] !~ /eri/ ) {
		$self->fail("Ramdisk not uploaded properly");
		return undef;
	}

	my @eki = split( /\s/, $eki_result[0] );
	my @eri = split( /\s/, $eri_result[0] );
	my @img = split( /\//, $dir );
	my $dircount  = @img - 1;
	my $imagename = $img[$dircount];
	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$imagename.img --ramdisk $eri[1] -d bundle --kernel $eki[1]");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-image-bucket -m bundle/$imagename.img.manifest.xml");
	my @emi_result = $self->sys("$self->{TOOLKIT}register $prefix-image-bucket/$imagename.img.manifest.xml");
	my @emi = split( /\s/, $emi_result[0] );
	$self->set_timeout(120);
	$self->sys("rm -rf bundle");

	if ( $emi_result[0] !~ /emi/ ) {
		$self->fail("Image not uploaded properly");
		return undef;
	}

	return ( $emi[1], $eri[1], $eki[1] );

}

sub deregister_image {
	my $self  = shift;
	my $image = shift;
	$self->test_name("Deregistering image $image");

	## Execute deregister command
	my @dereg1 = $self->sys("$self->{TOOLKIT}deregister $image");

	##If there was no output fail
	if ( @dereg1 < 1 ) {
		$self->fail("Deregister image the first time did not return any output");
		return undef;
	} else {
		## Was the image in the output
		if ( $dereg1[0] =~ /$image/ ) {
			my @desc1 = $self->sys("$self->{TOOLKIT}describe-images | grep $image");
			## Is the image still in the desc-images output
			if ( @desc1 < 1 ) {
				$self->fail("Image $image removed from describe images on first deregister");
				return undef;
			} else {
				## Need to deregister a second time to remove it if its in deregistered
				if ( $desc1[0] =~ /deregistered/ ) {
					my @dereg2 = $self->sys("$self->{TOOLKIT}deregister $image");

					if ( @dereg2 < 1 ) {
						$self->fail("Deregister image the second time did not return any output");
						return undef;
					} else {
						my @desc2 = $self->sys("$self->{TOOLKIT}describe-images | grep $image");
						if ( @desc2 < 1 ) {
							$self->pass("Successfully deregistered image $image");
							my @image_info = split( /\s/, $desc1[0] );
							my @bucket     = split( /\//, $image_info[2] );
							$self->delete_bundle("$bucket[0]");
							return $image;
						} else {
							$self->fail("Image still in store\n@desc2");
							return undef;
						}
					}

				} else {
					$self->fail("Image not in deregistered state\n$desc1[0]\n");
					return undef;
				}

			}

		}
	}
	return undef;

}

sub delete_bundle {
	my $self         = shift;
	my $bundle       = shift;
	my @deletebundle = $self->sys("$self->{TOOLKIT}delete-bundle --clear -b $bundle");
	if ( @deletebundle < 1 ) {
		$self->pass("Delete bundle seems to have succeeded");
		return 0;
	} else {
		$self->fail("Output returned from delete-bundle\n@deletebundle");
		return undef;
	}

}

sub run_instance {
	my $self      = shift;
	my $keypair   = shift;
	my $group     = shift;
	my $OPTS      = shift;
	my $time      = time();
	my $inst_hash = {};
	if ( !defined $keypair ) {
		$keypair = $self->add_keypair( "keypair-" . $time );
	}
	if ( !defined $group ) {
		$group = "group-" . $time;
		$self->add_group($group);

	}

	my $emi = $self->get_emi();

	$self->test_name("Sending run instance command");
	my $base_command = "$self->{TOOLKIT}run-instances -g $group -k $keypair  $emi";
	my @flags        = ();

	my @run_output = $self->sys($base_command);
	if ( @run_output < 1 ) {
		$self->fail("Initial attempt at running instance returned nothing");
		return undef;
	}

	### There was output to the run instance command, check if it includes INSTANCE
	my @instance_output = grep( /INSTANCE/, @run_output );
	if ( @instance_output < 1 ) {
		$self->fail("Initial attempt at running instance returned:\n@run_output");
		return undef;
	}

	### Check for state pending of the INSTANCE right after the run instance command
	if ( !( $instance_output[0] =~ /pending/ ) ) {
		$self->fail("Instance not in pending state after run");
		return $inst_hash;
	}

	my @instance_line_breakout = split( ' ', $instance_output[0] );
	my $instance_id = $instance_line_breakout[1];

	### Waiting for a few seconds
	$self->test_name("Sleeping ${INST_AVAILABLE_TIMEOUT_SEC} seconds for instance to become available");
	sleep $INST_AVAILABLE_TIMEOUT_SEC;
	$inst_hash = $self->get_instance_info($instance_id);
	## If emi- is found then we can assume we have the rest of the info as well
	if ( $inst_hash->{'emi'} !~ /emi-/ ) {
		$self->fail("Could not find the instance in the describe instances pool after issuing run and waiting ${INST_AVAILABLE_TIMEOUT_SEC}s");
		return $inst_hash;
	}
	$self->pass("Instance $inst_hash->{'id'}  started with emi $inst_hash->{'emi'}  at $inst_hash->{'time'}");

	### Poll the instance every 20s for 300s until it leaves the pending state
	my $period = 20;
	my $count  = 0;
	while ( ( $inst_hash->{'state'} eq "pending" ) && ( $count < 30 ) ) {
		$self->test_name("Polling every 20s until instance in running state");
		sleep $period;

		$inst_hash = $self->get_instance_info($instance_id);

		if ( $inst_hash->{'emi'} !~ /emi/ ) {
			$self->fail("Could not find the instance in the describe instances pool");
			return $inst_hash;
		}
		$count++;
	}

	### If the instance is not running after 300s there was an error
	if ( $inst_hash->{'state'} ne "running" ) {
		$self->fail( "Instance went from pending to $inst_hash->{'state'}  after " . ( $count * $period ) . "s" );
		return $inst_hash;
	}

	### Wait for instance to obtain an IP (other than 0.0.0.0)
	if ( !$inst_hash->{'pub-ip'} =~ /0\.0\.0\.0/ ) {
		sleep $INST_IP_TIMEOUT_SEC;
		$inst_hash = $self->get_instance_info($instance_id);

		if ( $inst_hash->{'pub-ip'} =~ /0\.0\.0\.0/ ) {
			$self->fail("Instance did not get an address within ${INST_IP_TIMEOUT_SEC}s");
			return $inst_hash;
		}
	}

	### Returns ($instance_id,  $emi, $ip, $state);
	$self->pass( "Instance is now in $inst_hash->{'state'}  state after " . ( $count * $period ) . " seconds" );
	return $inst_hash;
}

sub terminate_instance {
	my $self        = shift;
	my $instance_id = shift;
	my @output      = $self->sys("$self->{TOOLKIT}terminate-instances $instance_id");
	if ( @output < 1 ) {
		$self->fail("Terminate instance command failed");
		return undef;
	}
	if ( $output[0] =~ /$instance_id/ ) {
		sleep 30;
		my @describe_instances = $self->sys("$self->{TOOLKIT}describe-instances | grep $instance_id");
		if ( @describe_instances < 1 ) {
			$self->fail("After terminating instance it is no longer found in the describe instances output");
			return undef;
		}
		my @instance = split( ' ', $describe_instances[0] );
		if ( $instance[5] =~ /terminated/ ) {
			$self->pass("Successfully terminated instance $instance_id");
			return $instance_id;
		} else {
			$self->fail("Unable to terminate $instance_id, stuck in $instance[5] state");
			return undef;
		}
	} else {
		$self->fail("Unable to terminate $instance_id");
		return undef;
	}

}

sub get_instance_info {
	my $self        = shift;
	my $instance_id = shift;
	my $inst_hash   = {};
	my @running     = $self->sys("$self->{TOOLKIT}describe-instances $instance_id | grep INSTANCE");
	if ( @running < 1 ) {
		$self->fail("Did not find the instance in the describe instances pool");
		return $inst_hash;
	} else {
		my @info = split( /\s+/, $running[0] );

		$inst_hash->{"id"}      = $info[1];
		$inst_hash->{"emi"}     = $info[2];
		$inst_hash->{"pub-ip"}  = $info[3];
		$inst_hash->{"priv-ip"} = $info[4];
		$inst_hash->{"state"}   = $info[5];
		## TAKE CARE OF CASE WHERE no keypair is given
		#			if( $info[6] =~ /[0-255]/){
		#				$inst_hash->{"keypair"} =  "";
		#				$inst_hash->{"type"} = $info[7];
		#				$inst_hash->{"time"} = $info[8];
		#				$inst_hash->{"az"} = $info[9];
		#				$inst_hash->{"eki"} = $info[10];
		#				$inst_hash->{"eri"} = $info[11];
		#			}else{
		$inst_hash->{"keypair"} = $info[6];
		$inst_hash->{"type"}    = $info[8];
		$inst_hash->{"time"}    = $info[9];
		$inst_hash->{"az"}      = $info[10];
		$inst_hash->{"eki"}     = $info[11];
		$inst_hash->{"eri"}     = $info[12];

		#}
		print Dumper($inst_hash);
		return $inst_hash;
	}
}

sub get_volume_info {
	my $self        = shift;
	my $volume_id   = shift;
	my $vol_info    = {};
	my @volume_desc = $self->sys("$self->{TOOLKIT}describe-volumes $volume_id | grep VOLUME");
	if ( @volume_desc < 1 ) {
		$self->fail("Did not find the volume in the describe volumes pool");
		return $vol_info;
	} else {
		my @info = split( /\s+/, $volume_desc[0] );

		$vol_info->{"id"}        = $info[1];
		$vol_info->{"size"}      = $info[2];
		$vol_info->{"zone"}      = $info[3];
		$vol_info->{"state"}     = $info[4];
		$vol_info->{"timestamp"} = $info[5];

		print Dumper($vol_info);
		return $vol_info;
	}
}

sub teardown_instance {
	my $self        = shift;
	my $instance_id = shift;
	my $ip          = shift;
	$self->terminate_instance($instance_id);

	#sleep 30;
	#$self->release_address($ip);

}

sub reboot_instance {
	my $self        = shift;
	my $instance_id = shift;
	my $instance    = $self->get_instance_info($instance_id);
	my $ip          = $instance->{'ip'};
	my $keypair     = $instance->{'keypair'};
	my @uptime_old  = $self->sys("ssh root\@$ip -i $keypair.priv \"cat /proc/uptime | awk \'{print \$1}\'\"");
	my @output      = $self->sys("$self->{TOOLKIT}reboot-instances $instance_id");
	sleep 80;
	my @uptime_new = $self->sys("ssh root\@$ip -i $keypair.priv \"cat /proc/uptime | awk \'{print \$1}\'\"");

	if ( $uptime_old[0] > $uptime_new[0] ) {
		$self->pass("Instance rebooted. Old uptime: $uptime_old[0]  New uptime:  $uptime_new[0]");
		return $instance_id;
	} else {
		$self->fail("Uptime is greater than before reboot. Must not have rebooted instance properly");
		return undef;
	}
}

sub create_volume {
	my $self = shift;
	my $zone = shift;
	my $opts = shift;

	my $vol_timeout = 30;

	if ( !defined $zone ) {
		$self->fail("Required parameter zone not provided to function create_volume");
		return undef;
	}
	if ( !defined $opts->{"size"} && !defined $opts->{"snapshot"} ) {
		$self->fail("Required parameter size or snapshot not provided to function create_volume");
		return undef;
	}
	my $cmd = "$self->{TOOLKIT}create-volume -z $zone";

	if ( defined $opts->{"size"} ) {
		$cmd .= " -s " . $opts->{"size"};
	} elsif ( defined $opts->{"snapshot"} ) {
		$cmd .= " --snapshot " . $opts->{"snapshot"};
	}

	my @vol_create = $self->sys($cmd);

	my @vol_id = split( /\s+/, $vol_create[0] );

	if ( $vol_create[0] !~ /$vol_id[1].*creating.*/ ) {
		$self->fail("After running volume-create output does not show $vol_id[1] as creating");
		return undef;
	} else {
		sleep $vol_timeout;
		if ( !$self->found( "$self->{TOOLKIT}describe-volumes", qr/$vol_id[1].*$zone.*available.*/ ) ) {
			$self->fail("Unable to create volume");
			return undef;
		} else {
			$self->pass("Volume $vol_id[1] created properly");
			return $vol_id[1];
		}
	}

}

sub delete_volume {
	my $self   = shift;
	my $volume = shift;

	if ( !$self->found( "$self->{TOOLKIT}delete-volume $volume", qr/^VOLUME\s+$volume/ ) ) {
		$self->fail("Failed to delete volume");
		return undef;
	}
	sleep 5;
	if ( $self->found( "$self->{TOOLKIT}describe-volumes", qr/^VOLUME\s+$volume.*available/ ) ) {
		$self->fail("After delete volume still available");
		return undef;
	} else {
		return $volume;
	}

}

sub attach_volume {
	my $self     = shift;
	my $volume   = shift;
	my $instance = shift;
	my $device   = shift;
	if ( !defined $volume || !defined $instance || !defined $device ) {
		$self->fail("Missing parameters to EucaTest->attach_volume");
		return undef;
	}

	if ( !$self->found( "$self->{TOOLKIT}attach-volume $volume -i $instance -d $device", qr/^VOLUME\s+$volume/ ) ) {
		$self->fail("Attachment failed");
		return undef;
	}
	sleep 10;
	if ( !$self->found( "$self->{TOOLKIT}describe-volumes", qr/^VOLUME\s+$volume.*in-use/ ) ) {
		$self->fail("Attachment not appearing in describe volumes as in use");
		return undef;
	} else {
		return $volume;
	}
}

sub detach_volume {
	my $self   = shift;
	my $volume = shift;

	if ( !$self->found( "$self->{TOOLKIT}detach-volume $volume", qr/^VOLUME\s$volume/ ) ) {
		$self->fail("Detach command did not return correct status");
		return undef;
	}
	sleep 5;
	if ( !$self->found( "$self->{TOOLKIT}describe-volumes", qr/^VOLUME\s+$volume.*available/ ) ) {
		$self->fail("Volume still attached after 5 seconds");
		return undef;
	}

	return $volume;
}

sub create_snapshot {
	my $self          = shift;
	my $volume        = shift;
	my @create_output = $self->sys("euca-create-snapshot $volume");
	my $poll_interval = 20;
	my $poll_count    = 15;
	### Check that there was output from the create command
	if ( @create_output < 1 ) {
		$self->fail("Create snapshot returned without output");
		return undef;
	}
	{
		### If there was output check that it shows the SNAPSHOT as pending and the current percentage is increasing
		if ( $create_output[0] =~ /^SNAPSHOT.*pending/ ) {
			my @snapshot_info = split( / /, $create_output[0] );
			my $snap_id = $snapshot_info[1];
			$self->pass("Snapshot $snap_id being created and in pending state");
			my $old_percentage = 0;
			my $current_state  = "pending";

			while ( ( $poll_count > 0 ) && ( $current_state ne "completed" ) ) {
				sleep $poll_interval;
				my @snapshot_poll = $self->sys("euca-describe-snapshots | grep $snap_id");
				if ( @snapshot_poll < 1 ) {
					$self->fail("Did not find $snap_id in describe-snapshots");
					return undef;
				}
				my @snapshot_info  = split( / /, $snapshot_poll[0] );
				my @new_percentage = split( /%/, $snapshot_info[5] );
				if ( $new_percentage[0] > $old_percentage ) {
					$self->test_name("Snapshot went from $old_percentage to $new_percentage[0]");
					$old_percentage = $new_percentage[0];
					$current_state  = $snapshot_info[3];
					$poll_count--;

				} else {
					$self->fail("Snapshot at same percentage after $poll_interval");
					return undef;
				}

			}

			if ( $current_state eq "completed" ) {
				$self->pass("Successfully created snapshot $snap_id");
				return $snap_id;
			} else {
				$self->fail("Snapshot creation failed");
				return undef;
			}

		} else {
			$self->fail("Snapshot not in pending state after create");
			return undef;
		}
	}
}

sub delete_snapshot {
	my $self = shift;
	my $snap = shift;

	if ( $snap !~ /snap-/ ) {
		$self->fail("ERROR: invalid snapshot ID '$snap' for delete_snapshot");
		return undef;
	}

	my $cmd     = "$self->{TOOLKIT}delete-snapshot $snap";
	my @del_out = $self->sys($cmd);
	if ( @del_out < 1 ) {
		$self->fail("Delete snapshot returned no output");
		return undef;
	} elsif ( $del_out[0] !~ "snap-" ) {
		$self->fail("Deleting snapshot did not return snap-id\n");
		return undef;
	} else {

	}

	return $snap;
}

#### EUARE COMMANDS ########################

sub euare_create_account {
	my $self        = shift;
	my $new_account = shift;

	$self->sys("euare-accountcreate -a $new_account");
	if ( !$self->found( "euare-accountlist", qr/^$new_account/ ) ) {
		$self->fail("fail to add account $new_account");
		return undef;
	}
	return $new_account;
}

sub euare_delete_account {
	my $self            = shift;
	my $deleted_account = shift;
	$self->sys("euare-accountdel -a $deleted_account -r");
	if ( $self->found( "euare-accountlist", qr/^$deleted_account/ ) ) {
		$self->fail("failed to delete account $deleted_account");
		return undef;
	}
	return $deleted_account;
}

sub euare_create_user {
	my $self      = shift;
	my $new_user  = shift;
	my $account   = shift;
	my $user_path = shift;
	if ( !defined $user_path ) {
		$user_path = "/";
	}
	if ( !defined $account ) {
		$account = "eucalyptus";
	}
	$self->sys("euare-usercreate -u $new_user -p $user_path");
	if ( !$self->found( "euare-userlistbypath", qr/$new_user/ ) ) {
		$self->fail("could not create new user arn:aws:iam::$account:user$user_path$new_user");
		return undef;
	}
	$self->pass("Created new user arn:aws:iam::$account:user$user_path$new_user ");
	return $new_user;
}

sub euare_delete_user {
	my $self      = shift;
	my $new_user  = shift;
	my $account   = shift;
	my $user_path = shift;
	if ( !defined $user_path ) {
		$user_path = "/";
	}
	if ( !defined $account ) {
		$account = "eucalyptus";
	}
	$self->sys("euare-userdel -ru $new_user");
	if ( $self->found( "euare-userlistbypath", qr/arn:aws:iam::$account:user$user_path\/$new_user/ ) ) {
		$self->fail("could not delete user $new_user\@$account");
		return undef;
	}
	return 0;
}

sub euare_change_username {
	my $self          = shift;
	my $old_user_name = shift;
	my $new_user_name = shift;
	my $account       = shift;
	my $path          = shift;

	$self->sys("euare-usermod -u $old_user_name --new-user-name=$new_user_name");
	if ( !$self->found( "euare-userlistbypath", qr/arn:aws:iam::$account:user$path\/$new_user_name/ ) ) {
		$self->fail("failed to change user name");
		return undef;
	}
	return $new_user_name;
}

sub euare_clean_accounts {
	my $self     = shift;
	my @accounts = $self->sys("euare-accountlist");
	for my $account (@accounts) {
		chomp($account);
		my @pair = split( qr/\s+/, $account );
		if ( $pair[0] ne "eucalyptus" ) {
			$self->sys("euare-accountdel -a $pair[0] -r");
		}
	}
	@accounts = $self->sys("euare-accountlist");

	if ( @accounts > 1 || !( $accounts[0] =~ /^eucalyptus/ ) ) {
		$self->fail("failed to clean up accounts");
		return undef;
	}
	return 0;

}

sub euare_add_userinfo {
	my $self  = shift;
	my $user  = shift;
	my $key   = shift;
	my $value = shift;

	$self->test_name("Update $user info: $key=$value");
	$self->sys("euare-userupdateinfo -u $user -k $key -i $value");
	if ( !$self->found( "euare-usergetinfo -u $user", qr/$key\s+$value/ ) ) {
		$self->fail("failed to add user info");
	}
}

sub euare_create_loginprofile {
	my $self     = shift;
	my $user     = shift;
	my $password = shift;
	$self->sys("euare-useraddloginprofile -u $user -p $password");
	if ( !$self->found( "euare-usergetloginprofile -u $user", qr/^$user$/ ) ) {
		$self->fail("failed to add password");
		return undef;
	}
	return 0;
}

sub euare_delete_loginprofile {
	my $self = shift;
	my $user = shift;

	$self->sys("euare-userdelloginprofile -u $user");
	if ( $self->found( "euare-usergetloginprofile -u $user", qr/^$user$/ ) ) {
		$self->fail("there should be no password");
		return undef;
	}
	return 0;

}

sub euare_add_userkey {
	my $self = shift;
	my $user = shift;

	$self->sys("euare-useraddkey -u $user");
	my @res = $self->sys("euare-userlistkeys -u $user");
	if ( @res < 1 ) {
		$self->fail("failed to add access key");
		return undef;
	}

	my $key = $res[0];
	chomp($key);

	### ENSURE KEY IS FOUND
	if ( !$self->found( "euare-userlistkeys -u $user", qr/$key/ ) ) {
		$self->fail("failed to get user key");
		return undef;
	}
	$self->test_name("Check that key is active");
	if ( !$self->found( "euare-userlistkeys -u $user", qr/Active/ ) ) {
		$self->fail("wrong user key status");
		return undef;
	}
	return $key;

}

sub euare_deactivate_key {
	my $self = shift;
	my $user = shift;
	my $key  = shift;
	$self->test_name("Deactivate the key");
	$self->sys("euare-usermodkey -u $user -k $key -s Inactive");
	if ( !$self->found( "euare-userlistkeys -u $user", qr/Inactive/ ) ) {
		$self->fail("wrong user key status");
		return undef;
	}
	return 0;
}

sub euare_delete_key {
	my $self = shift;
	my $user = shift;
	my $key  = shift;

	$self->test_name("Delete the key");
	$self->sys("euare-userdelkey -u $user -k $key");
	if ( $self->found( "euare-userlistkeys -u $user", qr/$key/ ) ) {
		$self->fail("failed to delete user key");
		return undef;
	}
	return 0;
}

sub euare_create_cert {
	my $self = shift;
	my $user = shift;

	$self->test_name("create user certificate");
	$self->sys("euare-usercreatecert -u $user");
	my @res = $self->sys("euare-userlistcerts -u $user");
	if ( @res < 1 ) {
		$self->fail("failed to create certificate");
		return undef;
	}
	my $cert = $res[0];
	chomp($cert);
	$self->test_name("Check that certificate exists");
	if ( !$self->found( "euare-userlistcerts -u $user", qr/$cert/ ) ) {
		$self->fail("failed to get user cert");
		return undef;
	}

	$self->test_name("Check that cert is active");
	if ( !$self->found( "euare-userlistcerts -u $user", qr/Active/ ) ) {
		$self->fail("wrong user cert status");
		return undef;
	}
	return $cert;
}

sub euare_deactviate_cert {
	my $self = shift;
	my $user = shift;
	my $cert = shift;

	$self->test_name("Deactivate Cert");
	$self->sys("euare-usermodcert -u $user -c $cert -s Inactive");
	if ( !$self->found( "euare-userlistcerts -u $user", qr/Inactive/ ) ) {
		$self->fail("wrong user cert status");
		return undef;
	}
	return 0;
}

sub euare_delete_cert {
	my $self = shift;
	my $user = shift;
	my $cert = shift;
	$self->test_name("Delete cert");
	$self->sys("euare-userdelcert -u $user -c $cert");
	if ( $self->found( "euare-userlistcerts -u $user", qr/$cert/ ) ) {
		$self->fail("failed to delete user cert");
		return undef;
	}
}

sub euare_add_certfromfile {
	my $self     = shift;
	my $user     = shift;
	my $filename = shift;

	$self->test_name("Add user certificate from file");
	my @res  = $self->sys("euare-useraddcert -u $user -f $filename");
	my $cert = $res[0];
	chomp($cert);

	sleep(5);

	$self->test_name("Check that certificate exists");
	if ( !$self->found( "euare-userlistcerts -u $user", qr/$cert/ ) ) {
		$self->fail("failed to get user cert");
		return undef;
	}

	$self->test_name("Check that cert is active");
	if ( !$self->found( "euare-userlistcerts -u $user", qr/Active/ ) ) {
		$self->fail("wrong user cert status");
		return undef;
	}
	return $cert;
}

sub get_currentaccount {
	my $self = shift;
	my @cred_path = split( /-/, $self->{CREDPATH} );
	return $cred_path[1];
}

sub euare_create_group {
	my $self    = shift;
	my $group   = shift;
	my $path    = shift;
	my $account = $self->get_currentaccount();
	$self->sys("euare-groupcreate -g $group -p $path");
	if ( !$self->found( "euare-grouplistbypath", qr/arn:aws:iam::$account:group$path\/$group/ ) ) {
		$self->fail("could not create new group $group");
		return undef;
	}
	return $group;
}

sub euare_parse_arn {
	my $self = shift;
	my $type = shift;
	my $name = shift;

	my @group = $self->sys( "euare-" . $type . "listbypath | grep $name" );
	if ( @group < 1 ) {
		$self->fail("Unable to locate desired $type $name");
		return undef;
	}
	my @arn      = split( /:/, $group[0] );
	my $pathindx = @arn - 1;
	my @path     = split( /\//, $arn[$pathindx] );
	my $fullpath = "/";
	for ( my $counter = 1 ; $counter < @path - 1 ; $counter++ ) {
		$fullpath .= $path[$counter] . "/";
	}

	return $fullpath;

}

sub modify_property {
	my $self     = shift;
	my $property = shift;
	my $value    = shift;

	my $cmd = $self->{EUCADIR} . "/usr/sbin/euca-modify-property -p $property=$value";

	if ( !$self->found( $cmd, qr/$property/ ) ) {
		$self->fail("modify property failed for $property=$value");
	} else {
		$self->pass("set property $property to $value");
	}
}

sub euare_modattr {
	my $self    = shift;
	my $type    = shift;
	my $name    = shift;
	my $opts    = shift;
	my $account = $self->get_currentaccount();
	if ( !defined $type ) {
		$self->fail("Required parameter type not provided to function euare_modattr");
		return undef;
	}
	if ( !defined $opts->{"path"} && !defined $opts->{"newname"} ) {
		$self->fail("Required parameter path or name not provided to function euare_modattr");
		return undef;
	}
	my $path = $self->euare_parse_arn( $type, $name );
	my $cmd = "euare-" . $type . "mod";
	if ( $type eq "group" ) {
		$cmd .= " -g $name";
	} else {
		$cmd .= " -u $name";
	}

	if ( defined $opts->{"path"} ) {
		$cmd .= " -n " . $opts->{"path"};
		$path = $opts->{"path"};
	} elsif ( defined $opts->{"newname"} ) {
		$cmd .= " --new-group-name " . $opts->{"newname"};
		$name = $opts->{"newname"};
	}

	$self->sys($cmd);
	if ( !$self->found( "euare-" . $type . "listbypath", qr/arn:aws:iam::$account:$type$path$name/ ) ) {
		$self->fail("failed to change group path");
	}
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

EucaTest - Perl extension for Testing Eucalyptus on the QA infrastructure 

=head1 SYNOPSIS

  use EucaTest;
  This module is intended to act on an Eucalyptus installation using euca2ools that are installed either locally or on a remote host.
  Both basic building blocks (ie running an arbitrary command on the remote machine) and high level test constructs (ie runnning an instance) are presented to allow test designers the highest level of flexibilty. 
  
=head1 METHODS

=head2 Constructor

=over 4

=item new( %OPTS )

Creates and returns a new EucaTest object. 
[LOCAL CONNECTION]
When no arguments are passed in the opts hash the default behavior is to start a local session.
[REMOTE CONNECTION]
In order to connect to a remote host the 'host' value must be passed in as follows: EucaTest->new({ host => "root:foobar\@myserver.org"})

Other optional parameters to pass in the %OPTS hash:
keypath=> this expects the path to a local private key file to use to authenticate the remote ssh session 


=back

=head2 Access

=over 4

=item $circle->center

Returns a list of the x,y coordinates 
of the center of the circle.

In scalar context, 
returns an array reference.

=item $circle->radius

Returns the radius of the circle.

=item $circle->area

Returns the area of the circle.

=back

=head2 EXPORT

None by default.


=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.23 with options

  -ACXn
	EucaTest is now working under the Eucalyptus QA system. 

=back



=head1 SEE ALSO

www.eucalyptus.com

=head1 AUTHOR

Victor Iglesias, E<lt>vic.iglesias@eucalyptus.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Victor Iglesias

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
