## Run Proxy Server

```bash
$ go run main.go
```

or in background

```bash
$ sh run.sh
```


## Create User

```bash
$ go run main.go adduser <username> <password>
```
after this you need reload app

or

```bash
$ sh add.sh <username> <password>
```
after this you don't need reload app

## Delete User

open users.json file and remove user after remove run this command

```bash
$ sh run.sh
```

## Show All User Traffic

```bash
$ go run main.go showtraffic
```

and you can open traffic.json and show users traffic :)

