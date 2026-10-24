LLARP Control bundle
====================

Contents
  install.sh       one-shot installer (run this)
  llarp/           llarpd source, including submodules
  llarp-control/   llarpctl command line tool (+ optional GTK GUI)
  VERSION          llarpd commit this bundle was made from

Install on a VPS (Debian/Ubuntu, Fedora or Arch):

  scp llarp-control-bundle.tar.gz user@vps:
  ssh user@vps
  tar xzf llarp-control-bundle.tar.gz
  cd llarp-control-bundle
  sudo ./install.sh                  # or: sudo ./install.sh --autostart --user root

This installs the build dependencies, builds and installs llarpd to /usr/local/bin,
installs llarpctl to /usr/local/bin, creates a config, adds the opennet bootstrap
and starts llarpd. Run ./install.sh --help for options. It's safe to run again.

Afterwards:
  llarpctl status                    # running? address?
  llarpctl log -f                    # watch llarpd's output
  llarpctl exit on && llarpctl fwd enable   # become an exit node
  llarpctl --help
