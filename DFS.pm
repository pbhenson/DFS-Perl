#
# DFS-Perl version 0.15
#
# Paul Henson <henson@acm.org>
#
# Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
#

package DCE::DFS;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT $AUTOLOAD);

use DCE::ACL;
use DCE::Registry;

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);

@EXPORT = qw();

$VERSION = '0.15';

sub AUTOLOAD {
    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined DCE::DFS macro $constname";
	}
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

bootstrap DCE::DFS $VERSION;

sub type_object {0}
sub type_default_object {1}
sub type_default_container {2}

sub acl {
    my ($path, $acl_type) = @_;
    my $self = {};
    $self->{acl_type} = ($acl_type ne "") ? ($acl_type) : type_object;
    my $entry;
    my $entry_key;
    my $pgo_name;
    my $status;

    ($self->{acl_h}, $status) = DCE::ACL->bind($path);
    return (undef, $status) if $status;

    $self->{manager} = $self->{acl_h}->get_manager_types->[0];

    ($self->{rgy}, $status) = DCE::Registry->site_open_query("");
    return (undef, $status) if $status;

    ($self->{acl_list}, $status) = $self->{acl_h}->lookup($self->{manager},
							  $self->{acl_type});
    return (undef, $status) if $status;

    $self->{acls} = $self->{acl_list}->acls;

    foreach $entry ($self->{acls}->entries) {
	$entry_key = $self->{acl_h}->type($entry->entry_info->{entry_type});
	if ($entry_key eq "user") {
	    ($pgo_name, $status) =
		$self->{rgy}->pgo_id_to_name($self->{rgy}->domain_person,
					     $entry->entry_info->{id}{uuid});
	    $entry_key .= ($status) ? (":<unknown>") : (":" . $pgo_name);
	}
	elsif ($entry_key eq "group") {
	    ($pgo_name, $status) =
		$self->{rgy}->pgo_id_to_name($self->{rgy}->domain_group,
					     $entry->entry_info->{id}{uuid});
	    $entry_key .= ($status) ? (":<unknown>") : (":" . $pgo_name);
	}
	$self->{entries}{$entry_key} = { entry_type => $entry->entry_info->{entry_type},
					 uuid => $entry->entry_info->{id}{uuid},
					 perms => $entry->perms,
				     };
    }

    bless($self, "DCE::DFS::acl");
    return ($self, 0);
}

sub DCE::DFS::acl::entries {
    my $self = shift;
    my %entries;
    my $entry_key;

    foreach $entry_key (keys %{$self->{entries}}) {
	$entries{$entry_key} = perms_to_text($self->{entries}{$entry_key}{perms});
    }

    return \%entries;
}

sub DCE::DFS::acl::entry {
    my $self = shift;
    my ($entry_key) = @_;

    if ($self->{entries}{$entry_key}) {
	return (perms_to_text($self->{entries}{$entry_key}{perms}));
    }
    else {
	return undef;
    }
}

sub DCE::DFS::acl::modify {
    my $self = shift;
    my ($entry_key, $text) = @_;
    my $entry_type;
    my $entry_name;
    my $uuid;
    my $status;

    if ($self->{entries}{$entry_key}) {
	$self->{entries}{$entry_key}{perms} = text_to_perms($text);
    }
    else {
	($entry_type, $entry_name) = split(/:/, $entry_key);
	if ($entry_type =~ /^user_obj$/) {
	    $self->{entries}{$entry_key}{entry_type} = DCE::ACL::type_user_obj;
	}
	elsif ($entry_type =~ /^group_obj$/) {
	    $self->{entries}{$entry_key}{entry_type} = DCE::ACL::type_group_obj;
	}
	elsif ($entry_type =~ /^other_obj$/) {
	    $self->{entries}{$entry_key}{entry_type} = DCE::ACL::type_other_obj;
	}
	elsif ($entry_type =~ /^any_other$/) {
	    $self->{entries}{$entry_key}{entry_type} = DCE::ACL::type_any_other;
	}
	elsif ($entry_type =~ /^mask_obj$/) {
	    $self->{entries}{$entry_key}{entry_type} = DCE::ACL::type_mask_obj;
	}
	elsif ($entry_type =~ /^user$/) {
	    ($uuid, $status) = 
		$self->{rgy}->pgo_name_to_id($self->{rgy}->domain_person, $entry_name);
	    return $status if $status;
	    $self->{entries}{$entry_key}{entry_type} = DCE::ACL::type_user;
	    $self->{entries}{$entry_key}{uuid} = $uuid;
	}
	elsif ($entry_type =~ /^group$/) {
	    ($uuid, $status) = 
		$self->{rgy}->pgo_name_to_id($self->{rgy}->domain_group, $entry_name);
	    return $status if $status;
	    $self->{entries}{$entry_key}{entry_type} = DCE::ACL::type_group;
	    $self->{entries}{$entry_key}{uuid} = $uuid;
	}
	else {
	    return -1;
	}
	$self->{entries}{$entry_key}{uuid} = "" unless ($self->{entries}{$entry_key}{uuid});
	$self->{entries}{$entry_key}{perms} = text_to_perms($text),
    }
    return 0;
}


sub DCE::DFS::acl::delete {
    my $self = shift;
    my ($entry_key) = @_;

    if ($self->{entries}{$entry_key}) {
	undef $self->{entries}{$entry_key};
    }
}

sub DCE::DFS::acl::deleteall {
    my $self = shift;

    undef $self->{entries};
}

sub DCE::DFS::acl::calc_mask {
    my $self = shift;
    my $entry_key;
    my $mask_perms;

    foreach $entry_key (keys %{$self->{entries}}) {
	next if ($self->{entries}{$entry_key}{entry_type} == DCE::ACL->type_user_obj);
	next if ($self->{entries}{$entry_key}{entry_type} == DCE::ACL->type_mask_obj);
	$mask_perms |= $self->{entries}{$entry_key}{perms};
    }

    if (!($self->{entries}{mask_obj})) {
	$self->{entries}{mask_obj}{entry_type} = DCE::ACL::type_mask_obj;
        $self->{entries}{mask_obj}{uuid} = "";
    }
    $self->{entries}{mask_obj}{perms} = $mask_perms;
}

sub DCE::DFS::acl::commit {
    my $self = shift;
    my $entry;
    my $entry_key;
    my $status;

    if (!($self->{entries}{user_obj})) {
	$self->{entries}{user_obj}{entry_type} = DCE::ACL::type_user_obj;
	$self->{entries}{user_obj}{uuid} = "";
	$self->{entries}{user_obj}{perms} = 0;
    }

    $self->{entries}{user_obj}{perms} |= DCE::ACL->perm_control;

    if (!($self->{entries}{group_obj})) {
        $self->{entries}{group_obj}{entry_type} = DCE::ACL::type_group_obj;
        $self->{entries}{group_obj}{uuid} = "";
	$self->{entries}{group_obj}{perms} = 0;
    }

    if (!($self->{entries}{other_obj})) {
        $self->{entries}{other_obj}{entry_type} = DCE::ACL::type_other_obj;
        $self->{entries}{other_obj}{uuid} = "";
	$self->{entries}{other_obj}{perms} = 0;
    }

    if (!($self->{entries}{mask_obj})) {
	$self->calc_mask;
    }

    $self->{acls}->delete;

    foreach $entry_key (keys %{$self->{entries}}) {
	$entry = $self->{acls}->new_entry;
	$entry->entry_info({ entry_type => $self->{entries}{$entry_key}{entry_type},
			     id => {
				 uuid => $self->{entries}{$entry_key}{uuid},
				 name => "",
			     },
			 });
	$entry->perms($self->{entries}{$entry_key}{perms});
	$status = $self->{acls}->add($entry);
	return $status if $status;
    }

    $status = $self->{acl_h}->replace($self->{manager}, $self->{acl_type}, $self->{acl_list});
    return $status;
}

sub perms_to_text {
    my ($perms) = @_;
    my $text;

    $text .= ($perms & DCE::ACL->perm_read) ? "r" : "-";
    $text .= ($perms & DCE::ACL->perm_write) ? "w" : "-";
    $text .= ($perms & DCE::ACL->perm_execute) ? "x" : "-";
    $text .= ($perms & DCE::ACL->perm_control) ? "c" : "-";
    $text .= ($perms & DCE::ACL->perm_insert) ? "i" : "-";
    $text .= ($perms & DCE::ACL->perm_delete) ? "d" : "-";

    return $text;
}

sub text_to_perms {
    my ($text) = @_;
    my $perms;

    $perms |= DCE::ACL->perm_read if ($text =~ /r/);
    $perms |= DCE::ACL->perm_write if ($text =~ /w/);
    $perms |= DCE::ACL->perm_execute if ($text =~ /x/);
    $perms |= DCE::ACL->perm_control if ($text =~ /c/);
    $perms |= DCE::ACL->perm_insert if ($text =~ /i/);
    $perms |= DCE::ACL->perm_delete if ($text =~ /d/);

    return $perms;
}


1;
__END__


=head1 NAME

DCE::DFS - Perl extension interfacing with DFS

=head1 SYNOPSIS

  use DCE::DFS;

=head1 DESCRIPTION

To be done later.

=head1 AUTHOR

Paul Henson, <henson@acm.org>

=head1 SEE ALSO

perl(1).

=cut
