#
#    fty-lib-certificate - Library of helpers for ssl certificate
#
#    Copyright (C) 2019 - 2020 Eaton
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# To build with draft APIs, use "--with drafts" in rpmbuild for local builds or add
#   Macros:
#   %_with_drafts 1
# at the BOTTOM of the OBS prjconf
%bcond_with drafts
%if %{with drafts}
%define DRAFTS yes
%else
%define DRAFTS no
%endif
Name:           fty-lib-certificate
Version:        1.0.0
Release:        1
Summary:        library of helpers for ssl certificate
License:        GPL-2.0+
URL:            https://42ity.org
Source0:        %{name}-%{version}.tar.gz
Group:          System/Libraries
# Note: ghostscript is required by graphviz which is required by
#       asciidoc. On Fedora 24 the ghostscript dependencies cannot
#       be resolved automatically. Thus add working dependency here!
BuildRequires:  ghostscript
BuildRequires:  asciidoc
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  pkgconfig
BuildRequires:  xmlto
BuildRequires:  gcc-c++
BuildRequires:  openssl-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
fty-lib-certificate library of helpers for ssl certificate.

%package -n libfty_lib_certificate1
Group:          System/Libraries
Summary:        library of helpers for ssl certificate shared library

%description -n libfty_lib_certificate1
This package contains shared library for fty-lib-certificate: library of helpers for ssl certificate

%post -n libfty_lib_certificate1 -p /sbin/ldconfig
%postun -n libfty_lib_certificate1 -p /sbin/ldconfig

%files -n libfty_lib_certificate1
%defattr(-,root,root)
%{_libdir}/libfty_lib_certificate.so.*

%package devel
Summary:        library of helpers for ssl certificate
Group:          System/Libraries
Requires:       libfty_lib_certificate1 = %{version}
Requires:       openssl-devel

%description devel
library of helpers for ssl certificate development tools
This package contains development files for fty-lib-certificate: library of helpers for ssl certificate

%files devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libfty_lib_certificate.so
%{_libdir}/pkgconfig/libfty_lib_certificate.pc
%{_mandir}/man3/*
%{_mandir}/man7/*

%prep

%setup -q

%build
sh autogen.sh
%{configure} --enable-drafts=%{DRAFTS}
make %{_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}

# remove static libraries
find %{buildroot} -name '*.a' | xargs rm -f
find %{buildroot} -name '*.la' | xargs rm -f


%changelog
