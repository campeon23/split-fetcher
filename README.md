
# :rocket: Multi-Source Downloader

The Multi-Source Downloader is a highly efficient application crafted in Go. It takes a file, fragments it into **n parts**, and then downloads them concurrently in a highly optimized way. As a cherry on top, it then reassembles the final file, either through **Etag** or **Hash validation**, ensuring the file's integrity. And there's more...

![Downloader Graphic](./images/downloader.png)

## :pushpin: Features

* Split file download into parts
* Concurrent download
* File integrity validation via Etag or Hash
* And many more...

## :wrench: Usage

```ruby
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
```

## Building the Application

To build the application, you need to execute the following command:

```ruby
$ go build multi-source-downloader.go
```

This command will compile the application and generate an executable binary named multi-source-downloader. This binary will be located in the same directory where the command was executed.

## Running the Application

To run the application directly without creating a binary, you can use the following command:

```ruby
$ go run multi-source-downloader.go -s $sha_sums -u $url_file -k
```

## Using the Binary

All examples provided in the following sections of this document use the multi-source-downloader binary to run the application. Once the binary is built, you can use it directly to execute the program without needing to use the go run command.

## Examples:

1. To run the multi-source-downloader application in its default mode. In this mode, the application is instructed to download a file from the URL that is provided as a parameter (in this case, $url_file).
&nbsp;
      The application follows a few steps in default mode:

      **Splitting:** The application splits the file into two separate parts. This is the default split number if no other value is passed to the application. The downloaded parts are saved in the application's root directory.

      **Manifest File Creation:** Once all parts are downloaded, their metadata is saved into a manifest file. This file keeps track of all the necessary information about the parts, which will be used later in the assembling process.

      **Assembling:** The application uses the manifest file to assemble the downloaded parts back into a single file. The assembled file is saved in the application's root directory.

      **Validation:** Once the final file is assembled, the application checks its integrity by comparing it with the ETag returned by the server. This step ensures that the downloaded and assembled file matches exactly with the original file on the server.

      **Note:** If you want to change the number of parts the file is split into or change the directory where the files are saved, those options are configurable in the application. 

```ruby
$ url_file="https://ftp.halifax.rwth-aachen.de/ubuntu-releases/23.04/ubuntu-23.04-netboot-amd64.tar.gz"

$ ./multi-source-downloader -u $url_file
```

2. To direct the multi-source-downloader to download a file from $url_file in 100 parts, using a maximum of 20 connections concurrently, and validates the integrity of the download using SHA sums from $shasums.

```ruby
$ shasums="https://ftp.halifax.rwth-aachen.de/ubuntu-releases/23.04/SHA256SUMS"
$ url_file="https://ftp.halifax.rwth-aachen.de/ubuntu-releases/23.04/ubuntu-23.04-netboot-amd64.tar.gz"

$ ./multi-source-downloader -s $shasums -u $url_file -n 100 -c 20
```

1. To run the multi-source-downloader to download a file from $url_file, specified by -u, in 10 parts (-n 10), with a maximum of 5 connections at a time (-c 5). The parts are downloaded to the download_parts directory (-p download_parts), and the integrity of the downloaded file is verified using the SHA sums from $shasums (-s $shasums). The part files are kept after assembly (-k).


```ruby
$ ./multi-source-downloader -s $shasums -u $url_file -n 10 -c 5 -d -p download_parts -k
```

1. To use the multi-source-downloader to decrypt an encrypted manifest file, specified by $encrypted_manifest.

```ruby
encrypted_manifest="~/.config/.multi-source-downloader/ubuntu-23.04-netboot-amd64.manifest.51628721468495e921b639a4121e7342.json.enc"

$ ./multi-source-downloader -m $encrypted_manifest -f
```

&nbsp;
           **Note:** To decrypt the manifest file, access to the parts files is essential. These files, which are integral to the assembly of the final file, must be reachable for the application to operate properly. If the application cannot access these parts files, the decryption process will fail and the assembly of the final file will not be possible. Therefore, before you run the application, ensure that the parts files are accessible.

1. The following example instructs the multi-source-downloader to assemble parts, stored in the parts_test directory and defined by the specified manifest file ($manifest), into a final file named output.tar.gz within the assembled directory.

```go
$ manifest="~/.config/.multi-source-downloader/ubuntu-23.04-netboot-amd64.manifest.51628721468495e921b639a4121e7342.json"

$ ./multi-source-downloader -m $manifest -p parts_test -o assembled/output.tar.gz -a
```

## :zap: Fast & Concurrent

This tool breaks your downloads into parts and fetches them concurrently, making it lightening fast :zap:

![Downloader Graphic](./images/concurrency.png)

## :balance_scale: Balancing the Load

By setting the number of connections, you have control over how many parts of the file are downloaded at the same time. If set to 0, the application automatically balances the load.

## :gear: Control Your Parts

Choose how many parts you want to split your download into, the location of the parts, and even the naming prefix. You're in control.

## :white_check_mark: Integrity Validation

Ensure your download's integrity and authenticity with Hash or Etag validation.

## :globe_with_meridians: Open Source

Feel free to contribute and make this tool even more awesome!

## :page_with_curl: License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE) file for reference.
