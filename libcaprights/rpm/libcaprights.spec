#
# spec file for package libcaprights
#
# Copyright (c) 2015 Alex Richardson <arichardson.kde@gmail.com>
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.
#
# See also http://en.opensuse.org/openSUSE:Shared_library_packaging_policy

Name:           libcaprights0
Version:        0.1.4
Release:        0
Summary:        Userspace support library for Capsicum security framework
License:        BSD
Group:          System/Libraries
Url:            https://github.com/google/capsicum-test
Source0:        %{name}-%{version}.tar.xz
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  glibc-devel

%description
This package holds the libcaprights userspace library, which allows
userspace programs to use the Capsicum security features provided
by modern Linux kernels.  In particular this library provides
cap_enter(3), cap_getmode(3), cap_rights_init(3), cap_rights_set(3),
cap_rights_clear(3), cap_rights_is_set(3), cap_rights_merge(3),
cap_rights_remove(3), cap_rights_contains(3),
cap_rights_get(3), cap_rights_limit(3), cap_ioctls_get(3),
cap_ioctls_limit(3), cap_fcntls_get(3), cap_fcntls_limit(3),
pdfork(2), pdkill(2), pdgetpid(2), pdwait4(2).


%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name} = %{version}

%description    devel
This package provides the <sys/capsicum.h> header file that holds
declarations for the Capsicum functionality provided by the
%{name} package, plus development libraries.

%prep
%setup -q

%build
autoreconf -iv
%configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}
find %{buildroot} -name '*.la' -exec rm -f {} ';'

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%doc
%{_libdir}/libcaprights.so.%{version}
%{_libdir}/libcaprights.so.0

%files devel
%doc
%{_mandir}/*
%{_includedir}/sys/capsicum.h
%{_includedir}/sys/procdesc.h
%{_libdir}/libcaprights.a
%{_libdir}/libcaprights.so

%changelog
