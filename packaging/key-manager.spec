Name:       key-manager
Summary:    Central Key Manager and utilities
Version:    0.1.18
Release:    1
Group:      System/Security
License:    Apache-2.0 and BSL-1.0
Source0:    %{name}-%{version}.tar.gz
Source1002: key-manager-pam-plugin.manifest
Source1003: key-manager-listener.manifest
Source1004: libkey-manager-client.manifest
Source1005: libkey-manager-client-devel.manifest
Source1006: libkey-manager-common.manifest
Source1007: key-manager-tests.manifest
BuildRequires: cmake
BuildRequires: zip
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: libattr-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(libsystemd-journal)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(capi-system-info)
BuildRequires: pkgconfig(security-manager)
BuildRequires: pkgconfig(cynara-client-async)
BuildRequires: pkgconfig(cynara-creds-socket)
BuildRequires: pkgconfig(libtzplatform-config)
BuildRequires: boost-devel
Requires(pre): pwdutils
Requires(pre): tizen-platform-config-tools
Requires(postun): pwdutils
Requires: libkey-manager-common = %{version}-%{release}
%{?systemd_requires}

%global user_name key-manager
%global group_name key-manager
%global service_name key-manager
%global _rundir /run
%global smack_domain_name System
%global rw_data_dir %{?TZ_SYS_DATA:%TZ_SYS_DATA/ckm/}%{!?TZ_SYS_DATA:/opt/data/ckm/}
%global ro_data_dir %{?TZ_SYS_SHARE:%TZ_SYS_SHARE/ckm/}%{!?TZ_SYS_SHARE:/usr/share/ckm/}
%global db_test_dir %{?TZ_SYS_SHARE:%TZ_SYS_SHARE/ckm-db-test/}%{!?TZ_SYS_SHARE:/usr/share/ckm-db-test/}
%global initial_values_dir %{rw_data_dir}initial_values/

%description
Central Key Manager daemon could be used as secure storage
for certificate and private/public keys. It gives API for
application to sign and verify (DSA/RSA/ECDSA) signatures.

%package -n key-manager-listener
Summary:    Package with listener daemon
Group:      System/Security
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(capi-appfw-package-manager)
Requires:   libkey-manager-client = %{version}-%{release}

%description -n key-manager-listener
Listener for central key manager. This daemon is responsible for
receive notification from dbus about uninstall application
and pass them to key-manager daemon.

%package -n libkey-manager-common
Summary:    Central Key Manager (common libraries)
Group:      Development/Libraries
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libkey-manager-common
Central Key Manager package (common library)

%package -n libkey-manager-client
Summary:    Central Key Manager (client)
Group:      Development/Libraries
Requires:   key-manager = %{version}-%{release}
Requires:   libkey-manager-common = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libkey-manager-client
Central Key Manager package (client)

%package -n libkey-manager-client-devel
Summary:    Central Key Manager (client-devel)
Group:      Development/Libraries
BuildRequires: pkgconfig(capi-base-common)
Requires:   pkgconfig(capi-base-common)
Requires:   libkey-manager-client = %{version}-%{release}

%description -n libkey-manager-client-devel
Central Key Manager package (client-devel)

%package -n key-manager-tests
Summary:    Internal test for key-manager
Group:      Development
BuildRequires: pkgconfig(libxml-2.0)
Requires:   boost-test
Requires:   key-manager = %{version}-%{release}

%description -n key-manager-tests
Internal test for key-manager implementation.

%package -n key-manager-pam-plugin
Summary:    CKM login/password module to PAM
Group:      Development/Libraries
BuildRequires: pam-devel
Requires:   key-manager = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n key-manager-pam-plugin
CKM login/password module to PAM. Used to monitor user login/logout
and password change events from PAM


%prep
%setup -q
cp -a %{SOURCE1002} .
cp -a %{SOURCE1003} .
cp -a %{SOURCE1004} .
cp -a %{SOURCE1005} .
cp -a %{SOURCE1006} .
cp -a %{SOURCE1007} .

%build
%if 0%{?sec_build_binary_debug_enable}
    export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
    export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
    export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif


export LDFLAGS+="-Wl,--rpath=%{_libdir},-Bsymbolic-functions "

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON \
        -DSYSTEMD_UNIT_DIR=%{_unitdir} \
        -DSYSTEMD_ENV_FILE="/etc/sysconfig/central-key-manager" \
        -DRUN_DIR:PATH=%{_rundir} \
        -DSERVICE_NAME=%{service_name} \
        -DUSER_NAME=%{user_name} \
        -DGROUP_NAME=%{group_name} \
        -DSMACK_DOMAIN_NAME=%{smack_domain_name} \
        -DMOCKUP_SM=%{?mockup_sm:%mockup_sm}%{!?mockup_sm:OFF} \
        -DRW_DATA_DIR=%{rw_data_dir} \
        -DRO_DATA_DIR=%{ro_data_dir} \
        -DINITIAL_VALUES_DIR=%{initial_values_dir} \
        -DDB_TEST_DIR=%{db_test_dir}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{initial_values_dir}
mkdir -p %{buildroot}/etc/security/
mkdir -p %{buildroot}%{ro_data_dir}/scripts
mkdir -p %{buildroot}/etc/gumd/userdel.d/
cp data/scripts/*.sql %{buildroot}%{ro_data_dir}/scripts
cp doc/initial_values.xsd %{buildroot}%{ro_data_dir}
cp doc/sw_key.xsd %{buildroot}%{ro_data_dir}
cp data/gumd/10_key-manager.post %{buildroot}/etc/gumd/userdel.d/

mkdir -p %{buildroot}%{db_test_dir}
cp tests/testme_ver1.db %{buildroot}%{db_test_dir}
cp tests/testme_ver2.db %{buildroot}%{db_test_dir}
cp tests/testme_ver3.db %{buildroot}%{db_test_dir}
cp tests/XML_1_okay.xml %{buildroot}%{db_test_dir}
cp tests/XML_1_okay.xsd %{buildroot}%{db_test_dir}
cp tests/XML_1_wrong.xml %{buildroot}%{db_test_dir}
cp tests/XML_1_wrong.xsd %{buildroot}%{db_test_dir}
cp tests/XML_2_structure.xml %{buildroot}%{db_test_dir}
cp tests/XML_3_encrypted.xml %{buildroot}%{db_test_dir}
cp tests/XML_3_encrypted.xsd %{buildroot}%{db_test_dir}
cp tests/XML_4_device_key.xml %{buildroot}%{db_test_dir}
cp tests/XML_4_device_key.xsd %{buildroot}%{db_test_dir}
cp tests/encryption-scheme/db/db-7654 %{buildroot}%{db_test_dir}/db-7654
cp tests/encryption-scheme/db/db-key-7654 %{buildroot}%{db_test_dir}/db-key-7654
cp tests/encryption-scheme/db/key-7654 %{buildroot}%{db_test_dir}/key-7654

%make_install
%install_service multi-user.target.wants central-key-manager.service
%install_service sockets.target.wants central-key-manager-api-control.socket
%install_service sockets.target.wants central-key-manager-api-storage.socket
%install_service sockets.target.wants central-key-manager-api-ocsp.socket
%install_service sockets.target.wants central-key-manager-api-encryption.socket

%pre
# fail if runtime dir variable is different than compilation time variable
if [ `tzplatform-get TZ_SYS_DATA | cut -d'=' -f2` != %{TZ_SYS_DATA} ]
then
    echo "Runtime value of TZ_SYS_DATA is different than the compilation time value. Aborting"
    exit 1
fi
if [ `tzplatform-get TZ_SYS_SHARE | cut -d'=' -f2` != %{TZ_SYS_SHARE} ]
then
    echo "Runtime value of TZ_SYS_SHARE is different than the compilation time value. Aborting"
    exit 1
fi

# User/group (key-manager/key-manager) should be already added in passwd package.
# This is our backup plan if passwd package will not be configured correctly.
id -g %{group_name} > /dev/null 2>&1
if [ $? -eq 1 ]; then
    groupadd %{group_name} -r > /dev/null 2>&1
fi

id -u %{user_name} > /dev/null 2>&1
if [ $? -eq 1 ]; then
    useradd -d /var/lib/empty -s /sbin/nologin -r -g %{group_name} %{user_name} > /dev/null 2>&1
fi

%clean
rm -rf %{buildroot}

%post
# move data from old path to new one
# we have to assume that in case of TZ_SYS_DATA change some upgrade script will move all the data
if [ -d "/opt/data/ckm" ]
then
    cp -a /opt/data/ckm/. %{rw_data_dir} && rm -rf /opt/data/ckm
fi

systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start central-key-manager.service
fi

if [ $1 = 2 ]; then
    # update

    # In ckm version <= 0.1.18 all files were owned by root.
    find %{rw_data_dir} -exec chsmack -a %{smack_domain_name} {} \;
    chown %{user_name}:%{group_name} -R %{rw_data_dir}
    systemctl restart central-key-manager.service
fi


%preun
if [ $1 = 0 ]; then
    # unistall
    systemctl stop central-key-manager.service
fi

%postun
if [ $1 = 0 ]; then
    # unistall
    systemctl daemon-reload
fi

%post -n libkey-manager-common -p /sbin/ldconfig
%post -n libkey-manager-client -p /sbin/ldconfig
%postun -n libkey-manager-common -p /sbin/ldconfig
%postun -n libkey-manager-client -p /sbin/ldconfig

%post -n key-manager-listener
systemctl daemon-reload
if [ $1 = 2 ]; then
    # update
    systemctl stop central-key-manager-listener.service
fi

%preun -n key-manager-listener
if [ $1 = 0 ]; then
    # unistall
    systemctl stop central-key-manager-listener.service
fi

%postun -n key-manager-listener
if [ $1 = 0 ]; then
    # unistall
    systemctl daemon-reload
fi


%files -n key-manager
%manifest key-manager.manifest
%license LICENSE
%license LICENSE.BSL-1.0
%{_bindir}/key-manager
%{_unitdir}/multi-user.target.wants/central-key-manager.service
%{_unitdir}/central-key-manager.service
%{_unitdir}/central-key-manager.target
%{_unitdir}/sockets.target.wants/central-key-manager-api-control.socket
%{_unitdir}/central-key-manager-api-control.socket
%{_unitdir}/sockets.target.wants/central-key-manager-api-storage.socket
%{_unitdir}/central-key-manager-api-storage.socket
%{_unitdir}/sockets.target.wants/central-key-manager-api-ocsp.socket
%{_unitdir}/central-key-manager-api-ocsp.socket
%{_unitdir}/sockets.target.wants/central-key-manager-api-encryption.socket
%{_unitdir}/central-key-manager-api-encryption.socket
%dir %{_datadir}/ckm
%{_datadir}/ckm/initial_values.xsd
%{_datadir}/ckm/sw_key.xsd
%attr(770, %{user_name}, %{group_name}) %{rw_data_dir}
%attr(770, %{user_name}, %{group_name}) %{initial_values_dir}
%{_datadir}/ckm/scripts/*.sql
/etc/opt/upgrade/230.key-manager-change-data-dir.patch.sh
/etc/opt/upgrade/231.key-manager-migrate-dkek.patch.sh
/etc/opt/upgrade/232.key-manager-change-user.patch.sh
/etc/gumd/userdel.d/10_key-manager.post
%{_bindir}/ckm_tool

%files -n key-manager-pam-plugin
%manifest key-manager-pam-plugin.manifest
%{_libdir}/security/pam_key_manager_plugin.so*

%files -n key-manager-listener
%manifest key-manager-listener.manifest

%files -n libkey-manager-common
%manifest libkey-manager-common.manifest
%{_libdir}/libkey-manager-common.so.*

%files -n libkey-manager-client
%manifest libkey-manager-client.manifest
%license LICENSE
%{_libdir}/libkey-manager-client.so.*
%{_libdir}/libkey-manager-control-client.so.*

%files -n libkey-manager-client-devel
%manifest libkey-manager-client-devel.manifest
%{_libdir}/libkey-manager-client.so
%{_libdir}/libkey-manager-control-client.so
%{_libdir}/libkey-manager-common.so
%{_includedir}/ckm/ckm/ckm-manager.h
%{_includedir}/ckm/ckm/ckm-manager-async.h
%{_includedir}/ckm/ckm/ckm-certificate.h
%{_includedir}/ckm/ckm/ckm-control.h
%{_includedir}/ckm/ckm/ckm-error.h
%{_includedir}/ckm/ckm/ckm-key.h
%{_includedir}/ckm/ckm/ckm-password.h
%{_includedir}/ckm/ckm/ckm-pkcs12.h
%{_includedir}/ckm/ckm/ckm-raw-buffer.h
%{_includedir}/ckm/ckm/ckm-type.h
%{_includedir}/ckm/ckmc/ckmc-manager.h
%{_includedir}/ckm/ckmc/ckmc-control.h
%{_includedir}/ckm/ckmc/ckmc-error.h
%{_includedir}/ckm/ckmc/ckmc-type.h
%{_libdir}/pkgconfig/*.pc

%files -n key-manager-tests
%manifest key-manager-tests.manifest
%{_bindir}/ckm-tests-internal
%dir %{_datadir}/ckm-db-test
%{_datadir}/ckm-db-test/testme_ver1.db
%{_datadir}/ckm-db-test/testme_ver2.db
%{_datadir}/ckm-db-test/testme_ver3.db
%{_datadir}/ckm-db-test/XML_1_okay.xml
%{_datadir}/ckm-db-test/XML_1_okay.xsd
%{_datadir}/ckm-db-test/XML_1_wrong.xml
%{_datadir}/ckm-db-test/XML_1_wrong.xsd
%{_datadir}/ckm-db-test/XML_2_structure.xml
%{_datadir}/ckm-db-test/XML_3_encrypted.xml
%{_datadir}/ckm-db-test/XML_3_encrypted.xsd
%{_datadir}/ckm-db-test/XML_4_device_key.xml
%{_datadir}/ckm-db-test/XML_4_device_key.xsd
%{_datadir}/ckm-db-test/db-7654
%{_datadir}/ckm-db-test/db-key-7654
%{_datadir}/ckm-db-test/key-7654
%{_datadir}/ckm-db-test/encryption-scheme.p12
%{_bindir}/ckm_so_loader
%{_bindir}/ckm_db_tool
%{_bindir}/ckm_generate_db

