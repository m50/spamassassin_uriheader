#################################################################
#                                                               #
# Created by Markus at TitanHQ                                  #
# Copyright (c) 2006-2017, Copperfasten Technologies, Teoranta. #
# Version 1.0.0                                                 #
#                                                               #
#################################################################

=head1 NAME

URIHeader - perform regexp tests against the HEAD of a URI

=head1 SYNOPSIS

    loadplugin Mail::Spamassassin::Plugin::URIHeader
    uriheader      NAME_OF_RULE       Content-Type =~ /application\/foo/

=head1 DESCRIPTION

This plugin allows regexp rule to be written against the headers found in
a HEAD request against a URI

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

=item uriheader NAME_OF_RULE Header-Name =~ /pattern/modifiers

Specify a rule. C<NAME_OF_RULE> is the name of the rule to be used,
C<Header-Name> is the name of the HEAD header to check, and 
C</pattern/modifiers> is the Perl regular expression to match against this.

Header names are considered case-insensitive

=back

=cut

package Mail::SpamAssassin::Plugin::URIHeader;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Util qw(untaint_var);
use LWP::UserAgent;
use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);
our @TEMPORARY_METHODS = ();

our $modulename = "URIHeader";

sub new {
    my ($class, $mailsa) = @_;

    # the usual perlobj boilerplate to create a subclass object
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    # then register an eval rule, if desired...
    $self->set_config($mailsa->{conf});
    $self->register_method_priority('parsed_metadata', 0);
    $self->{caching} = 0;

    # and return the new plugin object
    dbg("$modulename: NOTIF: Loaded");
    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;

    my $pluginobj = $self;

    push(@cmds, {
        setting => 'uriheader',
        code => sub {
            my ($self, $key, $value, $line) = @_;
            local ($1,$2,$3,$4);
            if ($value !~ /^(\S+)\s+(\S+)\s*\=\~\s*(.+)$/) {
              return $Mail::SpamAssassin::Conf::INVALID_VALUE;
            }

            my $rulename = untaint_var($1);
            my $hdrname = $2;
            my $pattern = $3;

            return unless $self->{parser}->is_delimited_regexp_valid($rulename, $pattern);
            $pattern = Mail::SpamAssassin::Util::make_qr($pattern);
            return $Mail::SpamAssassin::Conf::INVALID_VALUE unless $pattern;

            $self->{uriheader_tests}->{$rulename} = {
                hdr => $hdrname,
                pattern => $pattern
            };
            my $evalfunc = "_uriheader_eval_$rulename";
            $evalfunc =~ s/[^a-zA-Z0-9_]/_/gs;
            return if (defined &{'Mail::SpamAssassin::Plugin::URIHeader::'.$evalfunc});
            $self->{parser}->add_test($rulename, $evalfunc."()", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
            my $evalcode = '
                sub Mail::SpamAssassin::Plugin::URIHeader::'.$evalfunc.'{ 
                    $_[0]->eval_hook_called($_[1], q{'.$rulename.'});
                }
            ';
            eval
                $evalcode . '; 1'
            or do {
                my $eval_stat = $@ ne '' ? $@ : "errno=$!"; chomp $eval_stat;
                warn "$modulename: pluginerror: $eval_stat\n";
                return $Mail::SpamAssassin::Conf::INVALID_VALUE;
            };
            $pluginobj->register_eval_rule($evalfunc);

            push @TEMPORARY_METHODS, "Mail::SpamAssassin::Plugin::URIHeader::${evalfunc}";
        }
    });
    push (@cmds, {
        setting => 'uriheader_cache_dsn',
        default => '',
        is_priv => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
    });
    push (@cmds, {
        setting => 'uriheader_cache_username',
        default => '',
        is_priv => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
    });
    push (@cmds, {
        setting => 'uriheader_cache_password',
        default => '',
        is_priv => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
    });

    $conf->{parser}->register_commands(\@cmds);
}

sub eval_hook_called {
    my ($pobj, $scanner, $rulename) = @_;

    my $rule = $scanner->{conf}->{uriheader_tests}->{$rulename};
    my $hdr  = $rule->{hdr};
    my $pattern = $rule->{pattern};
    dbg("$modulename: $rulename: $hdr =~ $pattern");

    foreach my $uri ( $scanner->get_uri_list() ) {
        if(my $h = $scanner->{uri_headers}->{$uri}->{$hdr}) {
            dbg("$modulename: Header Check: $hdr = $h");
            if($h =~ ${pattern}) {
                ## Modify description of test to show the URL that it was found in
                my $description = $scanner->{conf}->{descriptions}->{$rulename};
                $description =~ s/(UR[IL]|[lL]ink)/$1 ($uri)/;
                $scanner->{conf}->{descriptions}->{$rulename} = $description;
                return 1;
            }
        }
    }
    return 0;
}

sub parsed_metadata {
    my ($self, $opts) = @_;
    my $scanner = $opts->{permsgstatus};

    ## Initialize Cache if enabled
    if($scanner->{conf}->{uriheader_cache_dsn} && ($scanner->{conf}->{uriheader_cache_username} || $scanner->{conf}->{uriheader_cache_dsn} =~ /SQLite/)) {
        eval {
            local $SIG{'__DIE__'};
            $self->{cache_dbh} = DBI->connect_cached(
                                                        $scanner->{conf}->{uriheader_cache_dsn}, 
                                                        $scanner->{conf}->{uriheader_cache_username}, 
                                                        $scanner->{conf}->{uriheader_cache_password},
                                                        {RaiseError => 1, PrintError => 0, InactiveDestroy => 1}
                                                    ) or die $!;
        };
        if($@){
            dbg("$modulename: warn: $@");
        } else {
            $self->{caching} = 1;
            dbg("$modulename: NOTIF: enabling caching");

            eval {
                local $SIG{'__DIE__'};
                $self->{cache_dbh}->do("
                    CREATE TABLE IF NOT EXISTS uriheader_cache (
                        uri TEXT PRIMARY KEY NOT NULL,
                        headers TEXT NOT NULL
                    )
                ");
            };
            if($@) {
                dbg("$modulename: warn: $@");
                $self->{caching} = 0;
            }
        }
    }

    my $ua = LWP::UserAgent->new;
    $ua->timeout(5);
    $ua->env_proxy;
    foreach my $uri ($scanner->get_uri_list()) {
        my $select = "SELECT * FROM uriheader_cache WHERE uri = '$uri';";
        my $cache_lookup = undef;
        $cache_lookup = $self->{cache_dbh}->selectrow_arrayref($select) if $self->{caching};
        if(defined($cache_lookup)) {
            dbg("$modulename: NOTIF: got cache hit on $uri");
            for my $line (split /(\n)/, $cache_lookup->[1]) {
                next if $line =~ /200\s+OK/i;
                my ($hdr, $value) = split /:/, $line;
                next if !$hdr || !$value;
                chomp $hdr;
                next if $hdr eq "";
                chomp $value;
                next if $value eq "";
                dbg("$modulename: $uri Found Header: Header: $hdr: $value");
                $scanner->{uri_headers}->{$uri}->{$hdr} = $value;
            }
        } else {
            my $res = $ua->head($uri);
            if($res->is_success) {
                my $headers = '';
                for my $line (split /(\n)/, $res->as_string) {
                    next if $line =~ /200\s+OK/i;
                    my ($hdr, $value) = split /:/, $line;
                    next if !$hdr || !$value;
                    chomp $hdr;
                    next if $hdr eq "";
                    chomp $value;
                    next if $value eq "";
                    $headers .= "$hdr: $value\n";
                    dbg("$modulename: $uri Found Header: Header: $hdr: $value");
                    $scanner->{uri_headers}->{$uri}->{$hdr} = $value;
                }
                if($self->{caching}) {
                    $headers =~ s/'/''/g;
                    $self->{cache_dbh}->do("INSERT INTO uriheader_cache (uri, headers) VALUES ('$uri', '$headers');");
                    dbg("$modulename: NOTIF: caching $uri");
                }
            }
        }
    }
}

sub finish_tests {
    my ($self, $params) = @_;

    foreach my $method (@TEMPORARY_METHODS) {
      undef &{$method};
    }
    @TEMPORARY_METHODS = ();      # clear for next time
}

1;