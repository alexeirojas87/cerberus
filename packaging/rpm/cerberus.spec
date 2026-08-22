Name:           cerberus
Version:        {{VERSION}}
Release:        1%{?dist}
Summary:        DLP firewall for LLM agents — blocks secrets and PII from leaving your machine

License:        MIT OR Apache-2.0
URL:            https://cerberus.dev
Source0:        https://github.com/alexeirojas87/cerberus/releases/download/v{{VERSION}}/cerberus-{{VERSION}}-linux-{{ARCH}}.tar.gz

# Pre-compiled binary: fixed BuildArch according to the artifact target.
#   - for x86_64  ->  BuildArch: x86_64
#   - for aarch64 ->  BuildArch: aarch64
BuildArch:      x86_64

Requires:       glibc >= 2.17
AutoReqProv:    no

%description
Cerberus is a DLP firewall for LLM agents: it blocks secrets and PII from
leaving your machine. Local CLI/daemon (Mode B) with reverse/forward proxy
for egress traffic, rule packs, redaction and a reversible vault.

%prep
%setup -c -T -q -n %{name}
tar xzf "%{SOURCE0}" -C %{_builddir}/%{name}

%build
# Pre-compiled static binary: nothing to build.

%install
install -D -m 0755 "%{_builddir}/%{name}/cerberus" "%{buildroot}%{_bindir}/cerberus"

%files
%{_bindir}/cerberus

%post
if [ -x %{_bindir}/cerberus ]; then
  %{_bindir}/cerberus --version >/dev/null 2>&1 || true
fi

%preun
if [ -x %{_bindir}/cerberus ]; then
  %{_bindir}/cerberus stop >/dev/null 2>&1 || true
fi

%postun
%{_bindir}/cerberus stop >/dev/null 2>&1 || true

%changelog
* Thu Aug 21 2026 Cerberus <maintainers@cerberus.dev> - {{VERSION}}-1
- Release {{VERSION}}.
- Binary packaging (tar.gz) with post/preun samples.