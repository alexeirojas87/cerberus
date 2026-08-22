# frozen_string_literal: true

# Cerberus — Homebrew formula (template de release).
#
# Este archivo ES Ruby válido, pero los placeholders {{...}} deben sustituirse
# por los valores reales del release ANTES de publicar el tap:
#
#   tools/release/fill_brew_formula.sh --version 0.1.0 --platforms dist/SHA256SUMS --out dist/cerberus.rb
#
# Placeholders:
#   {{VERSION}}                -> versión del release (0.1.0)
#   {{SHA256_MACOS_X86_64}}    -> sha256 de cerberus-<v>-macos-x86_64.tar.gz
#   {{SHA256_MACOS_AARCH64}}   -> sha256 de cerberus-<v>-macos-aarch64.tar.gz
#   {{SHA256_LINUX_X86_64}}    -> sha256 de cerberus-<v>-linux-x86_64.tar.gz
#   {{SHA256_LINUX_AARCH64}}   -> sha256 de cerberus-<v>-linux-aarch64.tar.gz
#
# Al publicarla, el archivo debe llamarse cerberus.rb (Homebrew deriva el nombre
# de la clase del nombre de fichero de la fórmula).

class Cerberus < Formula
  desc "DLP firewall for LLM agents — blocks secrets and PII from leaving your machine"
  homepage "https://cerberus.dev"
  license "MIT OR Apache-2.0"
  version "{{VERSION}}"

  CERBERUS_MACOS_X86_64_SHA256  = "{{SHA256_MACOS_X86_64}}"
  CERBERUS_MACOS_AARCH64_SHA256 = "{{SHA256_MACOS_AARCH64}}"
  CERBERUS_LINUX_X86_64_SHA256  = "{{SHA256_LINUX_X86_64}}"
  CERBERUS_LINUX_AARCH64_SHA256 = "{{SHA256_LINUX_AARCH64}}"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/alexeirojas87/cerberus/releases/download/v#{version}/cerberus-#{version}-macos-aarch64.tar.gz"
      sha256 CERBERUS_MACOS_AARCH64_SHA256
    else
      url "https://github.com/alexeirojas87/cerberus/releases/download/v#{version}/cerberus-#{version}-macos-x86_64.tar.gz"
      sha256 CERBERUS_MACOS_X86_64_SHA256
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
      Cerberus se instala en #{HOMEBREW_PREFIX}/bin/cerberus.
      Primer uso:
        cerberus init
        cerberus start
    EOS
  end

  test do
    system "#{bin}/cerberus", "--version"
  end
end