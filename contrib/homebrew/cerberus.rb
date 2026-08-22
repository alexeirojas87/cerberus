class Cerberus < Formula
  desc "DLP firewall for LLM agents — blocks secrets and PII from leaving your machine"
  homepage "https://cerberus.dev"
  version "0.1.0"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/alexeirojas87/cerberus/releases/download/v0.1.0/cerberus-0.1.0-macos-aarch64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Placeholder
    else
      url "https://github.com/alexeirojas87/cerberus/releases/download/v0.1.0/cerberus-0.1.0-macos-x86_64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Placeholder
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/alexeirojas87/cerberus/releases/download/v0.1.0/cerberus-0.1.0-linux-aarch64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Placeholder
    else
      url "https://github.com/alexeirojas87/cerberus/releases/download/v0.1.0/cerberus-0.1.0-linux-x86_64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Placeholder
    end
  end

  def install
    bin.install "cerberus"
  end

  test do
    system "#{bin}/cerberus", "--version"
  end
end