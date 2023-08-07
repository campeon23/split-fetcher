# Multi-Source Downloader :rocket:
The Multi-Source Downloader is a highly efficient application crafted in Go. It takes a file, fragments it into **n parts**, and then downloads them concurrently in a highly optimized way. As a cherry on top, it then reassembles the final file, either through **Etag** or **Hash validation**, ensuring the file's integrity. And there's more...

![Downloader Graphic](./images/downloader.png)

## :pushpin: Features
* Split file download into parts
* Concurrent download
* File integrity validation via Etag or Hash
* And many more...

## :wrench: Usage
```bash
multi-source-downloader [flags]

Flags:

  -a, --assemble-only          // (Optional) Assemble part files only if true and --parts-dir and --manifest flags are passed
  -f, --decrypt-manifest       // (Optional) If true, decrypts the manifest file
  -d, --download-only          // (Optional) Download part files only if true
  -h, --help                   // help for multi-source-downloader
  -k, --keep-parts             // (Optional) Whether to keep the parts files after assembly
  -m, --manifest-file string   // (Required by --assemble-only) Manifest file (must be decrypted) to pass to the main function
  -c, --max-connections int    // (Optional) Controls how many parts of the file are downloaded at the same time.
  -n, --num-parts int          // (Optional) Number of parts to split the download into (default 5)
  -o, --output string          // (Optional) Name and location of the final output file
  -p, --parts-dir string       // (Optional) The directory to save the parts files
  -x, --prefix-parts string    // (Optional) The prefix to use for naming the parts files (default "output-")
  -s, --sha-sums string        // (Optional) The URL of the file containing the hashes.
  -u, --url string             // (Required) URL of the file to download
  -v, --verbose                // (Optional) Output verbose logging (INFO and Debug), verbose not passed only output INFO logging.

Examples:

1.- This command directs the multi-source-downloader to download a file from $ubuntu_server in 100 parts, using a maximum of 20 connections concurrently, and validates the integrity of the download using SHA sums from $ubuntu_shasums.

```
ubuntu_shasums="https://ftp.halifax.rwth-aachen.de/ubuntu-releases/23.04/SHA256SUMS"
ubuntu_server="https://ftp.halifax.rwth-aachen.de/ubuntu-releases/23.04/ubuntu-23.04-netboot-amd64.tar.gz"

./multi-source-downloader -s $ubuntu_shasums -u $ubuntu_server -n 100 -c 20
```

2.- This example runs the multi-source-downloader to download a file from $ubuntu_server, specified by -u, in 10 parts (-n 10), with a maximum of 5 connections at a time (-c 5). The parts are downloaded to the download_parts directory (-p download_parts), and the integrity of the downloaded file is verified using the SHA sums from $ubuntu_shasums (-s $ubuntu_shasums). The part files are kept after assembly (-k), and verbose logging is enabled (-v).

```
./multi-source-downloader -s $ubuntu_shasums -u $ubuntu_server -n 10 -c 5 -d -p download_parts -k -v
```

3. The following command uses the multi-source-downloader to decrypt an encrypted manifest file, specified by $encrypted_manifest, with verbose logging enabled.
```
encrypted_manifest="~/.config/.multi-source-downloader/ubuntu-23.04-netboot-amd64.manifest.51628721468495e921b639a4121e7342.json.enc"

./multi-source-downloader -m $encrypted_manifest -f -v
```

4. The following example instructs the multi-source-downloader to assemble parts, stored in the parts_test directory and defined by the specified manifest file ($manifest), into a final file named output.tar.gz within the assembled directory, with verbose logging enabled.
```
manifest="~/.config/.multi-source-downloader/ubuntu-23.04-netboot-amd64.manifest.51628721468495e921b639a4121e7342.json"

./multi-source-downloader -m $manifest -p parts_test -o assembled/output.tar.gz -a -v
```
:zap: Fast & Concurrent
This tool breaks your downloads into parts and fetches them concurrently, making it lightening fast :zap:

Concurrency Image

:scales: Balancing the Load
By setting the number of connections, you have control over how many parts of the file are downloaded at the same time. If set to 0, the application automatically balances the load.

:gear: Control Your Parts
Choose how many parts you want to split your download into, the location of the parts, and even the naming prefix. You're in control.

:white_check_mark: Integrity Validation
Ensure your download's integrity and authenticity with Hash or Etag validation.

:globe_with_meridians: Open Source
Feel free to contribute and make this tool even more awesome!

:pencil: License
Include a short note about the license your project is using.

## :page_with_curl: License
This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE) file for reference.

MIT License

Copyright (c) 2023, Marco Villarruel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

