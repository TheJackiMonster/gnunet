XDG Scheme Handler for GNUnet URIs
==================================

To register the `gnunet://` URI scheme, launch the following commands from this
directory as a privileged user:

    install -Dm644 gnunet-uri.desktop /usr/share/applications/gnunet-uri.desktop
    update-mime-database /usr/share/applications/
