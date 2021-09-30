# SMART QR Links

This repository implements prototypes for a few different technical approach to
one core problem: how to make it easy and safe to share health data using QR
codes? See:  [use cases and technical approaches](https://hackmd.io/kvyVFD5cQK2Bg1_vnXSh_Q).

## Prepare

```sh
git clone https://github.com/jmandel/shclinks

cd shclinks
npm install

cd client-app
npm install
```

## Run


```sh
# Terminal 1
cd shclinks
npm run watch-oauth

# Terminal 2
cd client-app
npm run start
```

Open a local browser to http://localhost:3000 to view the client app

## Configure

This project comes pre-configured to use an Epic MyChart sandbox account (see [docs](https://fhir.epic.com/Documentation?docId=testpatients)). You can point it to a production MyChart account if you're feeling brave by copying `.env.sandbox` and tweaking the configuration params.

* Set `NODE_ENV` to use a different `.env` template (e.g., `NODE_ENV=jmandel` to use a `.env.jmandel` file with a different MyChart account configured)