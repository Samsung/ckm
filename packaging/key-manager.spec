Name:       key-manager
Summary:    Central Key Manager and utilities
Version:    0.1.14
Release:    1
Group:      System/Security
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: key-manager.manifest
Source1002: key-manager-listener.manifest
Source1003: libkey-manager-client.manifest
Source1004: libkey-manager-common.manifest
BuildRequires: cmake
BuildRequires: zip
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: libattr-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(libsystemd-journal)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: boost-devel
Requires: libkey-manager-common = %{version}-%{release}
%{?systemd_requires}

%description
Central Key Manager daemon could be used as secure storage
for certificate and private/public keys. It gives API for
application to sign and verify (DSA/RSA/ECDSA) signatures.

%package -n key-manager-listener
Summary:    Package with listener daemon
Group:      System/Security
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(glib-2.0)
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
Summary:    CKM login/password module to PAM.
Group:      Development/Libraries
BuildRequires: pam-devel
Requires:   key-manager = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n key-manager-pam-plugin
CKM login/password module to PAM.
It's used to monitor user login/logout and password change events from PAM.


%prep
%setup -q
cp -a %{SOURCE1001} .
cp -a %{SOURCE1002} .
cp -a %{SOURCE1003} .
cp -a %{SOURCE1004} .

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
%if "%{sec_product_feature_security_mdfpp_enable}" == "1"
        -DSECURITY_MDFPP_STATE_ENABLE=1 \
%endif
        -DSYSTEMD_UNIT_DIR=%{_unitdir} \
        -DSYSTEMD_ENV_FILE="/etc/sysconfig/central-key-manager"

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libkey-manager-client
cp LICENSE %{buildroot}/usr/share/license/libkey-manager-control-client
mkdir -p %{buildroot}/opt/data/ckm/initial_values
mkdir -p %{buildroot}/etc/security/
mkdir -p %{buildroot}/usr/share/ckm/scripts
cp data/scripts/*.sql %{buildroot}/usr/share/ckm/scripts
cp doc/initial_values.xsd %{buildroot}/usr/share/ckm
mkdir -p %{buildroot}/usr/share/ckm-db-test
cp tests/testme_ver1.db %{buildroot}/usr/share/ckm-db-test/
cp tests/testme_ver2.db %{buildroot}/usr/share/ckm-db-test/
cp tests/testme_ver3.db %{buildroot}/usr/share/ckm-db-test/
cp tests/XML_1_okay.xml %{buildroot}/usr/share/ckm-db-test/
cp tests/XML_1_okay.xsd %{buildroot}/usr/share/ckm-db-test/
cp tests/XML_1_wrong.xml %{buildroot}/usr/share/ckm-db-test/
cp tests/XML_1_wrong.xsd %{buildroot}/usr/share/ckm-db-test/
cp tests/XML_2_structure.xml %{buildroot}/usr/share/ckm-db-test/
mkdir -p %{buildroot}/etc/gumd/userdel.d/
cp data/gumd/10_key-manager.post %{buildroot}/etc/gumd/userdel.d/

%make_install
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
mkdir -p %{buildroot}%{_unitdir}/sockets.target.wants
ln -s ../central-key-manager.service %{buildroot}%{_unitdir}/multi-user.target.wants/central-key-manager.service
ln -s ../central-key-manager-listener.service %{buildroot}%{_unitdir}/multi-user.target.wants/central-key-manager-listener.service
ln -s ../central-key-manager-api-control.socket %{buildroot}%{_unitdir}/sockets.target.wants/central-key-manager-api-control.socket
ln -s ../central-key-manager-api-storage.socket %{buildroot}%{_unitdir}/sockets.target.wants/central-key-manager-api-storage.socket
ln -s ../central-key-manager-api-ocsp.socket %{buildroot}%{_unitdir}/sockets.target.wants/central-key-manager-api-ocsp.socket

%clean
rm -rf %{buildroot}

%post
systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start central-key-manager.service
fi

if [ $1 = 2 ]; then
    # update
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

%post -n libkey-manager-client -p /sbin/ldconfig

%postun -n libkey-manager-client -p /sbin/ldconfig

%post -n key-manager-listener
systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start central-key-manager-listener.service
fi
if [ $1 = 2 ]; then
    # update
    systemctl restart central-key-manager-listener.service
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
%{_datadir}/license/%{name}
%{_datadir}/ckm/scripts/*.sql
%{_datadir}/
%{_datadir}/ckm/initial_values.xsd
/opt/data/ckm/initial_values/
%attr(444, root, root) %{_datadir}/ckm/scripts/*.sql
/etc/opt/upgrade/230.key-manager-migrate-dkek.patch.sh
/etc/gumd/userdel.d/10_key-manager.post
%attr(550, root, root) /etc/gumd/userdel.d/10_key-manager.post
%{_bindir}/ckm_tool

%files -n key-manager-listener
%manifest key-manager-listener.manifest
%{_bindir}/key-manager-listener
%{_unitdir}/multi-user.target.wants/central-key-manager-listener.service
%{_unitdir}/central-key-manager-listener.service

%files -n libkey-manager-common
%manifest libkey-manager-common.manifest
%{_libdir}/libkey-manager-common.so.*

%files -n libkey-manager-client
%manifest libkey-manager-client.manifest
%{_libdir}/libkey-manager-client.so.*
%{_libdir}/libkey-manager-control-client.so.*
%{_datadir}/license/libkey-manager-client
%{_datadir}/license/libkey-manager-control-client

%files -n libkey-manager-client-devel
%defattr(-,root,root,-)
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
%defattr(-,root,root,-)
%{_bindir}/ckm-tests-internal
%{_datadir}/ckm-db-test/testme_ver1.db
%{_datadir}/ckm-db-test/testme_ver2.db
%{_datadir}/ckm-db-test/testme_ver3.db
%{_datadir}/ckm-db-test/XML_1_okay.xml
%{_datadir}/ckm-db-test/XML_1_okay.xsd
%{_datadir}/ckm-db-test/XML_1_wrong.xml
%{_datadir}/ckm-db-test/XML_1_wrong.xsd
%{_datadir}/ckm-db-test/XML_2_structure.xml
%{_bindir}/ckm_so_loader

%files -n key-manager-pam-plugin
%defattr(-,root,root,-)
%{_libdir}/security/pam_key_manager_plugin.so*
