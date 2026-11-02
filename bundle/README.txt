LLARP Control bundle
====================

Contents
  install.sh       one-shot installer (run this)
  llarp/           llarpd source, including submodules
  llarp-control/   llarpctl command line tool (+ optional GTK GUI)
  VERSION          llarpd commit this bundle was made from
  llarp-control/VERSION   llarp-control version in this bundle

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
  llarpctl status                    # running? address? stuck?
  llarpctl log -f                    # watch llarpd's output
  llarpctl exit on && llarpctl fwd enable   # become an exit node
  llarpctl --help

Update an existing install
  Unpack the new bundle and run its installer again, the same way as the first time
  (sudo ./install.sh, plus --user if you used it). Your settings, address and keys are kept.
  llarpd is only rebuilt if its version changed. A running llarpd is restarted to apply
  the update.

Keep an exit node working: run it under systemd
  After days of uptime llarpd can get stuck: it keeps running and keeps advertising
  itself, but can't build paths, so nobody can use the exit. llarpctl status shows
  "stuck" after 10 minutes. Under systemd, a watchdog restarts it automatically. (A VPN
  client is also restarted when no traffic gets through its exit for 3 minutes.)

    as root:        sudo ./install.sh --autostart --user root
    as your user:   llarpctl autostart on
                    sudo loginctl enable-linger $USER    # keep it running when logged out
                    llarpctl stop && systemctl --user start llarp-control
