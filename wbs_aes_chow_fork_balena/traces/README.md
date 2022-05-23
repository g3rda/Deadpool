## Usage

## Acquiring one trace with TracerPIN

```bash
Tracer -t sqlite -- ../target/aes128 57fc3136b432637710a00fe53e491308
```

Sqlite trace is about 11Mb large.

## Visualizing

Just fire tracegraph and load the sqlite trace:

```
tracegraph trace-full-info.sqlite &
```

We can see most AES rounds occur somewhere between 0x401AD5 and 0x4028A7.
