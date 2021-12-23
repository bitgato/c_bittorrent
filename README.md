# extorrent
An experimental bare-bones bittorrent client for linux written in C.
For concurrency, it uses non-blocking sockets on a single thread.
Implements only the most necessary things from
[this](https://wiki.theory.org/index.php/BitTorrentSpecification)
unofficial specification.
Made mostly for learning purposes but works well enough with cooperative peers.
Try downloading a popular open source software which provides torrents, like
[debian](https://cdimage.debian.org/debian-cd/current/amd64/bt-cd/)
or
[libreoffice](https://www.libreoffice.org/download/download/).

### libraries needed
- [curl](https://curl.se/libcurl/)
  (for sending GET request to the HTTP tracker)
- [openssl](https://www.openssl.org/)
  (for computing SHA1 hashes)

### usage
```
extorrent TORRENTFILE [FILENAME] [OPTION]

-v --verbose    explain what is being done
-h --help       print this help message and exit
```
Downloads the torrent in the `TORRENTFILE` file and saves it to `FILENAME`, if
specified, and to the name given in the torrent file otherwise.

### design choices
I decided not to use threads because I wanted to learn how non-blocking
(and blocking) sockets work in C. Beej's
[guide](https://www.beej.us/guide/bgnet/)
was a lot of help.

I used my own bencode
[parser](https://github.com/bitgato/bencode)
for this project.

There's a macro in `p2p.h` called `COMMTIMEOUT`. It is used as the
timeout (microseconds) for the `select` call in the main communication loop.
Increasing it reduces the CPU usage but can slow down the download. I set it
to 10000 microseconds as default. You can change it as per your needs. I found
that setting it to 1000 or 100 works fairly well too.

In the same header file, there's also `SIMULBLOCKS`. It's the number of blocks
we request to a peer simultaneously. Increasing it can increase the download
speed but if you set it too high, peers are more likely to choke us. I used
5 as default because, apparently, that's what the clients used classically.

We download the pieces in random order.
No special strategy (like the rarest-first) for selecting pieces has been
used, which sometimes leads to the problem: when all the peers we are connected
to (by the end) don't have a piece, that piece is just left undownloaded and
the client hangs.

We don't send `cancel` messages to peers after we get a piece in the "endgame".

### known issues
Someimes hangs when the peers connected have no pieces to download. See above.

### limitations
- Does not support uploading pieces (only leeching)
- Supports only single-file torrents
- No support for magnet links (only `.torrent` files)
- Only supports HTTP trackers
- No resume file option
- Contacts the tracker only once
