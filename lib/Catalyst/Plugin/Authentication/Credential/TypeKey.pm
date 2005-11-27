package Catalyst::Plugin::Authentication::Credential::TypeKey;

use strict;
use warnings;

use Authen::TypeKey;
use File::Spec;
use Catalyst::Utils ();
use NEXT;
use UNIVERSAL::require;
use Scalar::Util ();

our $VERSION = '0.1';

sub setup {
    my $c = shift;

    my $config = $c->config->{authentication}{typekey} ||= {};

    $config->{typekey_object} ||= do {
        ( $config->{user_class} ||=
              "Catalyst::Plugin::Authentication::User::Hash" )->require;

        $config->{key_cache} ||=
          File::Spec->catfile( Catalyst::Utils::class2tempdir( $c, 1 ),
            'regkeys.txt' );

        my $typekey = Authen::TypeKey->new;

        for ( grep { exists $config->{$_} }
            qw/expires key_cache key_url token version skip_expiry_check/ )
        {
            $typekey->$_( $config->{$_} );
        }

        $typekey;
    };

    $c->NEXT::setup(@_);
}

sub authenticate_typekey {
    my ( $c, @p ) = @_;

    my ( $user, $p );
    if ( @p == 1 ) {
        if ( Scalar::Util::blessed( $p[0] ) ) {
            $user = $p[0];
            Catalyst::Exception->throw(
                    "Attempted to authenticate user object, but "
                  . "user doesnt't support 'typekey_credentials'" )
              unless $user->supports(qw/typekey_credentials/);
            $p = $user->typekey_credentials;
        }
        else {
            $p = $p[0];
        }
    }
    else {
        $p = @p ? {@p} : undef;
    }

    my $config = $c->config->{authentication}{typekey};

    my $typekey = $p && delete( $p->{typekey_object} )
      || $config->{typekey_object};

    $p ||= $c->req;

    if ( my $res = $typekey->verify($p) ) {
        $c->log->debug("Successfully authenticated user '$res->{name}'.")
          if $c->debug;

        if ( !$user and my $store = $config->{auth_store} ) {
            $store = $c->get_auth_store($store) unless ref $store;
            $user = $store->get_user( $p, $res );
        }

        if ( !$user ) {
            my $user_class = $config->{user_class};
            $user = $user_class->new($res);
        }

        $c->set_authenticated($user);

        return 1;
    }
    else {
        $c->log->debug(
            sprintf "Failed to authenticate user '%s'. Reason: '%s'",
            $p->{name} || $p->param("name"),
            $typekey->errstr
          )
          if $c->debug;

        return;
    }
}

1;

__END__

=head1 NAME

Catalyst::Plugin::Authentication::Credential::TypeKey - TypeKey Authentication
for Catalyst.

=head1 SYNOPSIS

    use Catalyst qw/Authentication::Credential::TypeKey/;

    MyApp->config->{authentication}{typekey} = {
        token => 'xxxxxxxxxxxxxxxxxxxx',
    };

    sub foo : Local {
		my ( $self, $c ) = @_;

		if ( $c->authenticate_typekey ) {

		# you can also specify the params manually: $c->authenticate_typekey(
		#	name => $name,
		#	email => $email,
		#	...
		#)

			# successful autentication

			$c->user; # this is set
		}
	}


	sub auto : Private {
		my ( $self, $c ) = @_;

		$c->authenticate_typekey; # uses $c->req

		return 1;
	}

=head1 TYPEKEY BROKED-NESS

Please watch:

	http://rt.cpan.org/NoAuth/Bugs.html?Dist=Authen-TypeKey

I could only get this to properly work with TypeKey version 1 (not 1.1).

To get around this problem configure the plugin to use version 1:

	__PACKAGE__->config(
		authentication => {
			typekey => {
				version => 1,
				token => ..., # doesn't really matter in version 1
			},
		},
	);

=head1 DESCRIPTION

This module integrates L<Authen::TypeKey> with
L<Catalyst::Plugin::Authentication>.

=head1 METHODS

=item authenticate_typekey %parameters

=item authenticate_typekey

=item EXTENDED METHODS

=item setup

Fills the config with defaults.

=head1 CONFIGURATION

C<<$c->config->{autentication}{typekey}>> is a hash with these fields (all can
be left out):

=over 4

=item typekey_object

If this field does not exist an L<Authen::TypeKey> object will be created based
on the other param and put here.

=item expires

=item key_url

=item token

=item version

See L<Authen::TypeKey> for all of these. If they aren't specified
L<Authen::TypeKey>'s defaults will be used.

=item key_cache

Also see L<Authen::TypeKey>.

Defaults to C<regkeys.txt> under L<Catalyst::Utils/class2tempdir>.

=item auth_store

A store (or store name) to retrieve the user from.

When a user is successfully authenticated it will call this:

	$store->get_user( $parameters, $result_of_verify );

Where C<$parameters> is a the hash reference passed to
L<Authen::TypeKey/verify>, and C<$result_of_verify> is the value returned by
L<Authen::TypeKey/verify>.

If this is unset, L<Catalyst::Plugin::Authentication/default_auth_store> will
be used instead.

=item user_class

If C<auth_store> or the default store returns nothing from get_user, this class
will be used to instantiate an object by calling C<new> on the class with the
return value from L<Authen::TypeKey/verify>.

=back

=head1 SEE ALSO

L<Authen::TypeKey>, L<Catalyst>, L<Catalyst::Plugin::Authentication>.

=head1 AUTHOR

Christian Hansen

Yuval Kogman, C<nothingmuch@woobling.org>

=head1 LICENSE

This library is free software . You can redistribute it and/or modify it under
the same terms as perl itself.

=cut
