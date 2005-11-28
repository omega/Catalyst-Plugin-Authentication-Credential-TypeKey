use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl => 'traditional',
    license            => 'perl',
    module_name => 'Catalyst::Plugin::Authentication::Credential::TypeKey',
    requires    => {
        'Catalyst'                         => '5.5',
        'Catalyst::Plugin::Authentication' => 0,
        'Authen::TypeKey'                  => 0,

    },
    create_readme => 1,
    sign          => 1,
);
$build->create_build_script;

