Name:       key-manager
Summary:    Central Key Manager and utilities
Version:    0.1.3
Release:    1
Group:      System/Security
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires: cmake
BuildRequires: zip
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: libattr-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(db-util)
BuildRequires: pkgconfig(capi-appfw-package-manager)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: boost-devel
Requires: boost-test
%{?systemd_requires}

%description
Central Key Manager and utilities

%package -n key-manager-listener
Summary:    Package with listener daemon
Group:      System/Security
Requires:   libkey-manager-client = %{version}-%{release}

%description -n key-manager-listener
Listener for central key manager. This daemon is responsible for
receive notification from dbus about uninstall application
and notify central key manager about it.

%package -n libkey-manager-client
Summary:    Central Key Manager (client)
Group:      Development/Libraries
Requires:   key-manager = %{version}-%{release}
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
Summary:    internal test for key-manager
Group:      Development
Requires:   key-manager = %{version}-%{release}

%description -n key-manager-tests
Internal test for key-manager

%prep
%setup -q


%build
%if 0%{?sec_build_binary_debug_enable}
    export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
    export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
    export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif


export LDFLAGS+="-Wl,--rpath=%{_libdir} "

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON 
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libkey-manager-client
cp LICENSE %{buildroot}/usr/share/license/libkey-manager-control-client
mkdir -p %{buildroot}/etc/security/

%make_install
mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
mkdir -p %{buildroot}/usr/lib/systemd/system/sockets.target.wants
ln -s ../central-key-manager.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/central-key-manager.service
ln -s ../central-key-manager-api-control.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/central-key-manager-api-control.socket
ln -s ../central-key-manager-api-storage.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/central-key-manager-api-storage.socket
ln -s ../central-key-manager-api-ocsp.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/central-key-manager-api-ocsp.socket

%clean
rm -rf %{buildroot}

%post
%if "%{sec_product_feature_security_mdfpp_enable}" == "1"
rm %{_libdir}/libkey-manager-key-provider.so.1.0.0
ln -s %{_libdir}/libskmm.so %{_libdir}/libkey-manager-key-provider.so.1.0.0
%endif
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

%files -n key-manager
%manifest %{_datadir}/key-manager.manifest
%attr(755,root,root) /usr/bin/key-manager
%{_libdir}/libkey-manager-commons.so*
%{_libdir}/libkey-manager-key-provider.so*
%attr(-,root,root) /usr/lib/systemd/system/multi-user.target.wants/central-key-manager.service
%attr(-,root,root) /usr/lib/systemd/system/central-key-manager.service
%attr(-,root,root) /usr/lib/systemd/system/central-key-manager.target
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/central-key-manager-api-control.socket
%attr(-,root,root) /usr/lib/systemd/system/central-key-manager-api-control.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/central-key-manager-api-storage.socket
%attr(-,root,root) /usr/lib/systemd/system/central-key-manager-api-storage.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/central-key-manager-api-ocsp.socket
%attr(-,root,root) /usr/lib/systemd/system/central-key-manager-api-ocsp.socket
%{_datadir}/license/%{name}

%files -n key-manager-listener
%manifest %{_datadir}/key-manager-listener.manifest
%attr(755,root,root) /usr/bin/key-manager-listener

%files -n libkey-manager-client
%manifest %{_datadir}/libkey-manager-client.manifest
%manifest %{_datadir}/libkey-manager-control-client.manifest
%defattr(-,root,root,-)
%{_libdir}/libkey-manager-client.so.*
%{_libdir}/libkey-manager-control-client.so.*
%{_datadir}/license/libkey-manager-client
%{_datadir}/license/libkey-manager-control-client


%files -n libkey-manager-client-devel
%defattr(-,root,root,-)
%{_libdir}/libkey-manager-client.so
%{_libdir}/libkey-manager-control-client.so
%{_includedir}/ckm/ckm/ckm-manager.h
%{_includedir}/ckm/ckm/ckm-certificate.h
%{_includedir}/ckm/ckm/ckm-control.h
%{_includedir}/ckm/ckm/ckm-error.h
%{_includedir}/ckm/ckm/ckm-key.h
%{_includedir}/ckm/ckm/ckm-password.h
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
