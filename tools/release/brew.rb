# frozen_string_literal: true

# Cerberus — Homebrew formula (release template).
#
# This file IS valid Ruby, but the VERSION and SHA256 placeholders must be
# replaced with the real release values BEFORE publishing the tap:
#
#   tools/release/fill_brew_formula.sh --version 0.1.0 --platforms dist/SHA256SUMS --out dist/cerberus.rb
#
# Placeholders:
#   VERSION                    -> release version (0.1.0)
#   SHA256_MACOS_AARCH64       -> sha256 of cerberus-<v>-macos-aarch64.tar.gz
#   SHA256_LINUX_X86_64        -> sha256 of cerberus-<v>-linux-x86_64.tar.gz
#   SHA256_LINUX_AARCH64       -> sha256 of cerberus-<v>-linux-aarch64.tar.gz
#
# When publishing, the file must be named cerberus.rb (Homebrew derives the class
# name from the formula file name).
#
# Platform set (owner decision, commit 161387a): macOS releases are Apple
# Silicon only (aarch64). Intel (x86_64) macOS artifacts are NOT published —
# macos-13 Intel runners chronically stalled releases. Intel Mac users install
# via install.sh under Rosetta 2 or from source.

class Cerberus < Formula
  desc "DLP firewall for LLM agents — blocks secrets and PII from leaving your machine"
  homepage "https://cerberus.dev"
  license "MIT OR Apache-2.0"
  version "{{VERSION}}"

  CERBERUS_MACOS_AARCH64_SHA256 = "{{SHA256_MACOS_AARCH64}}"
  CERBERUS_LINUX_X86_64_SHA256  = "{{SHA256_LINUX_X86_64}}"
  CERBERUS_LINUX_AARCH64_SHA256 = "{{SHA256_LINUX_AARCH64}}"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/alexeirojas87/cerberus/releases/download/v#{version}/cerberus-#{version}-macos-aarch64.tar.gz"
      sha256 CERBERUS_MACOS_AARCH64_SHA256
    else
      # Intel macOS is not published (owner decision 161387a). Fail loudly
      # instead of downloading a non-existent artifact.
      odie "cerberus #{version} is published for Apple Silicon only; use install.sh from a Rosetta 2 shell or build from source"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/alexeirojas87/cerberus/releases/download/v#{version}/cerberus-#{version}-linux-aarch64.tar.gz"
      sha256 CERBERUS_LINUX_AARCH64_SHA256
    else
      url "https://github.com/alexeirojas87/cerberus/releases/download/v#{version}/cerberus-#{version}-linux-x86_64.tar.gz"
      sha256 CERBERUS_LINUX_X86_64_SHA256
    end
  end

  def install
    bin.install "cerberus"
  end

  def caveats
    <<~EOS
      Cerberus is installed at #{HOMEBREW_PREFIX}/bin/cerberus.
      First use:
        cerberus init
        cerberus start
    EOS
  end

  test do
    system "#{bin}/cerberus", "--version"
  end
end