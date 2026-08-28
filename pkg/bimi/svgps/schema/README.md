# SVG Tiny Portable/Secure schema

`SVG_PS-latest.rnc` is a verbatim copy of the schema published by the
AuthIndicators Working Group (BIMI Group) at

    https://bimigroup.org/resources/SVG_PS-latest.rnc.txt

`draft-svg-tiny-ps-abrotman-03` section 7 reproduces this schema and states that
the copy hosted at the URL above "is the one that should be used if there is any
conflict", which makes it the normative definition of the profile.

`SVG_PS-latest.rng` is the same schema in the RELAX NG XML syntax. It is the file
the code generator reads: the XML syntax is parsed with `encoding/xml` from the
standard library, whereas the compact syntax would require a hand-written parser
for no benefit.

## Refreshing the schema

Neither step is needed to build or test the project; run them only when the BIMI
Group publishes an update.

```sh
curl -o SVG_PS-latest.rnc https://bimigroup.org/resources/SVG_PS-latest.rnc.txt
uvx rnc2rng SVG_PS-latest.rnc > SVG_PS-latest.rng   # or: java -jar trang.jar in.rnc out.rng
go generate ./pkg/bimi/svgps/
go test ./pkg/bimi/...
```

The generator rejects any RELAX NG construct it does not already handle, so an
upstream change that alters the shape of the schema fails loudly instead of
silently weakening the validation.
