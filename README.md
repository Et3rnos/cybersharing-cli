# Cybersharing CLI

This is the official [Cybersharing](https://cybersharing.net^) CLI. It is a command line interface that allows you to interact with the Cybersharing API. You can use it to upload and download files via the terminal.

## Installation

Installing the Cybersharing CLI is easy. You can install it via pip:

```bash
pip install cybersharing
```

## Usage

### Login

Although **not required**, it is recommended that you login into your Cybersharing account before using the CLI. You can do this by running the following command:

```bash
cybersharing login <token>
```

Where `<token>` is your CLI Token. You can find it in your account settings.

You can logout at any time by running:

```bash
cybersharing logout
```

### Upload

To upload one or more files, you can run the following command:

```bash
cybersharing upload <file1> <file2> ...
```

Where `<file1>`, `<file2>`, etc. are the files you want to upload. 

Any option supported by the web interface is also supported by the CLI. For example, you can specify that the file should never expire by running:

```bash
cybersharing upload --permanent <file>
```

For the full list of options, run:

```bash
cybersharing upload --help
```

### Download

To download files from a Cybersharing url, you can run the following command:

```bash
cybersharing download <url>
```

A valid URL starts with `https://cybersharing.net/s/`.

Like with the upload command, you can specify options when downloading files. For example, you can download a password-protected file by running:

```bash
cybersharing download --password <password> <url>
```

Once again, for the full list of options, run:

```bash
cybersharing download --help
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.