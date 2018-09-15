% Actix-web
% Gabriela Surita

# Who am I?

# Another Web framework?!

## Flask

. . .

We all love Flask!

. . .

```Python
from flask import Flask


app = Flask(__name__)


@app.route("/", methods=("GET",))
def hello():
    return "world"


if __name__ == '__main__':
    app.run()
```

## Flask (Routes)

```python
@app.route('/user/<username>', methods=("GET",))
def get_profile(username):
    return jsonify({
        "name": username,
    })
```

## Flask (Body)

```python
@app.route('/user', methods=("POST",))
def create_profile(username):
    user = request.json

    # Deserialization
    # Error handling
    # Authz
    # ...
    # Do stuff

    return jsonify(user)
```

## Pytest

. . .

We all love Pytest!

. . .

```python
import pytest


@pytest.fixture
def user(payload):
    try:
        return User(payload)
    except ValueError as e:
        raise ValidationError(e.message)


@pytest.mark.parametrize("payload",
    ({"name": "John", "age": 17},)
def test_user(user):
    assert user
```

## What's this about?

What if?

. . .

- we could use depency injection in Web API views?
- Dependencies can work as "request guards"
- Validation, Authn/z, DB access are request Handlers
- Passed to views by type


## Rocket


```rust

#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    age:  Option<usize>
}

#[get("/users/<username>")]
fn get_profile(username: String) -> Json<User> {
    Json(User { name: username, age: None })
}

#[post("/users", data="<user>")]
fn create_profile(user: Json<User>) -> Json<User> {
    # Do stuff
    Json(user)
}
```

## Rocket (cont)

```rust
fn main() {
    rocket::ignite().mount("/", routes![
        get_profile,
        create_profile
    ])
    .launch();
}
```


## Actix


```rust

#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    age:  Option<usize>
}

fn get_profile(username: Path<String>) -> impl Responder {
    User { name: username, age: None }
}

fn create_profile(user: Json<User>) -> impl Responder {
    # Do stuff
    user
}
```

## Actix (cont)


```rust

fn main() {
    server::new(|| App::new()
            .resource("/user/<username>", |r| r.with(get_profile))
            .resource("/user", |r| r.with(create_profile))
        )
        .bind("127.0.0.1:8000")
        .expect("Failed to bind 8000")
        .run();
}
```

## Type safety

. . .

Real type safety, not casting.

. . .

- Yesod
- Spock
- Apistar
- Rocket
- Actix-web


# Rust Web Frameworks

## What we want

* Fast
* Type safe
* Flexible/Multi purpose

## Hyper

* Low-Level
* Asynchronous/Synchonous
* Base of iron, gotham, rocket, nickel, ...
* Large boilerplate
* Less fun

## Rocket

* Nice API
* Nice documentation
* Request Guards
* Fully Synchronous
* Requires Nightly

. . .

How to make Rocket faster?

. . .

Targetting stable Rust?

## Actix web

Rust's powerful actor system and most fun web framework

* Sep 24, 2017
* Jan 21, 2018
* Nikolay Kim (fafhrd91)


## Who's behind?

Nikolay Kim (fafhrd91)

. . .

* Works at Azure - IoT team
* PyO3. Rust-Python bridge
* Creator of aiohttp
* Core contributor to AsyncIO framework

## Release

![](images/tweet1.png)

## Community

![](images/tweet2.png)

![](images/tweet3.png)

## Features

* Built on top of Actix actor framework
* Support for HTTP/1.x and HTTP/2.0 protocols
* Streaming and pipelining
* Keep-alive and slow requests handling
* Client/server WebSockets support
* Configurable request routing

## Batteries included

* Transparent content compression/decompression (br, gzip, deflate)
* Graceful server shutdown
* Multipart streams
* Static assets
* SSL support with OpenSSL or native-tls
* Middleware (Logger, Session, Redis sessions, DefaultHeaders, CORS, CSRF)
* Includes an asynchronous HTTP client

## It's fast

It's really fast.

. . .

(ask about it in the end)

# Synchronous vs. Asynchronous

## Synchronous

. . .

Single Threaded:

![](images/sync1.png)

. . .

Multi-Threaded:

![](images/sync2.png)

https://codewala.net/2015/07/29/concurrency-vs-multi-threading-vs-asynchronous-programming-explained/


## Asynchronous

. . .

Single Threaded:

![](images/async1.png)

. . .

Multi-Threaded:

![](images/async2.png)


## Actor model

An actor is a computational entity that contains state information and can send, receive and handle messages.

![](images/actors.png)

https://www.brianstorti.com/the-actor-model/

## Actor model objectives

* Enforce encapsulation without resorting to locks.
* Use the model of cooperative entities reacting to signals, changing state and sending signals to each other to drive the whole application forward.
* Stop worrying about an executing mechanism which is a mismatch to our world view.


## Actix features

* Async/Sync actors
* Actor in a local/thread context
* Uses Futures for asynchronous message handling
* Supervision
* Typed messages

## Actor

```Rust
struct MyActor {
    count: usize,
}

impl Actor for MyActor {
    type Context = Context<Self>;
}
```

## Message

```Rust
struct Ping(usize);

impl Message for Ping {
    type Result = usize;
}
```

## Handler

```Rust
impl Handler<Ping> for MyActor {
    type Result = usize;

    fn handle(&mut self, msg: Ping, ctx: &mut Context<Self>) -> Self::Result {
        self.count += msg.0;

        self.count
    }
}
```

## System

```Rust
fn main() {
    let system = System::new("test");

    // start new actor
    let addr = MyActor{count: 10}.start();

    // send message and get future for result
    let res = addr.send(Ping(10));

    Arbiter::handle().spawn(
        res.map(|res| {
            println!("RESULT: {}", res == 20);
        });

    system.run();
}

```


# Thanks

# Code samples

## Hello World

```Rust
extern crate actix_web;
use actix_web::{server, App, Responder};

fn index() -> impl Responder {
    "Hello world!"
}

fn main() {
    server::new(|| App::new().resource("/", |r| r.with(index)))
        .bind("127.0.0.1:8000")
        .expect("Failed to bind 8000")
        .run();
}
```

## Application State

```Rust
extern crate actix_web;

use std::cell::Cell;
use actix_web::{server, App, State, Responder};

struct AppState {
    counter: Cell<usize>,
}

fn index(state: State<AppState>) -> impl Responder {
    let count = state.counter.get() + 1;
    state.counter.set(count);
    format!("Request number: {}", count)
}

fn main() {
    server::new(App::with_state(AppState { counter: Cell::new(0) })
            .resource("/", |r| r.with(index))
        )
        .bind("127.0.0.1:8000")
        .expect("Failed to bind 8000")
        .run();
}

```

---

Application state is shared with all routes and resources within the same application (`App`).


## Request handler

```Rust
fn index(_req: HttpRequest) -> &'static str {
    "Hello world!"
}
```

`Handler` trait: A request handler accepts an `HttpRequest` instance as parameter
and returns a type that can be converted into `HttpResponse` (`Responder` trait).


## Async handlers

```Rust
fn async(req: HttpRequest) -> impl Responder {
    result(Ok("Welcome!"))
        .responder()
}

fn main() {
    App::new()
        .resource("/async", |r| r.route().a(async)) // <- use `a`
        .finish();
}
```

## Path info extraction

```Rust
/// extract path info from "/{username}/{count}/index.html" url
/// {username} - deserializes to a String
/// {count} -  - deserializes to a u32
fn index(info: Path<(String, u32)>) -> Result<String> {
    Ok(format!("Welcome {}! {}", info.0, info.1))
}

fn main() {
    let app = App::new().resource(
        "/{username}/{count}/index.html", // <- define path parameters
        |r| r.method(http::Method::GET).with(index) // <- use `with` extractor
        .finish();
    );
}
```

---

Option 2: Access by calling extract() on the extractor

```Rust
use actix_web::FromRequest;

fn index(req: HttpRequest) -> HttpResponse {
    let params = Path::<(String, String)>::extract(&req);
    let info = Json::<MyInfo>::extract(&req);

    ...
}
```

## Path info extraction with structs

```Rust
#[derive(Deserialize)]
struct Info {
    username: String,
}

/// extract path info using serde
fn index(info: Path<Info>) -> Result<String> {
    Ok(format!("Welcome {}!", info.username))
}

```

## Query parameter extraction

```Rust
#[derive(Deserialize)]
struct Info {
    username: String,
}

// this handler get called only if request's query contains `username` field
fn index(info: Query<Info>) -> String {
    format!("Welcome {}!", info.username)
}

fn main() {
    let app = App::new().resource(
       "/index.html",
       |r| r.method(http::Method::GET).with(index)); // <- use `with` extractor
}
```

## JSON in requests

```Rust
#[derive(Deserialize)]
struct Info {
    username: String,
}

/// deserialize `Info` from request's body
fn index(info: Json<Info>) -> Result<String> {
    Ok(format!("Welcome {}!", info.username))
}

fn main() {
    let app = App::new().resource(
       "/index.html",
       |r| r.method(http::Method::POST).with(index));  // <- use `with` extractor
}
```

## JSON in responses

```Rust
#[derive(Serialize)]
struct MyObj {
    name: String,
}

fn index(req: HttpRequest) -> Result<Json<MyObj>> {
    Ok(Json(MyObj {
        name: req.match_info().query("name")?,
    }))
}
```

## Form handling

```Rust
#[derive(Deserialize)]
struct FormData {
    username: String,
}

fn index(form: Form<FormData>) -> Result<String> {
     Ok(format!("Welcome {}!", form.username))
}
```

## Multiple extractors

```Rust
fn index((path, query): (Path<(u32, String)>, Query<Info>)) -> String {
    format!("Welcome {}!", query.username)
}

fn main() {
    let app = App::new().resource(
       "/users/{userid}/{friend}",
       |r| r.method(http::Method::GET).with(index));
}
```

Actix provides extractor implementations for tuples (up to 10 elements) whose elements implement FromRequest.

## Request routing

```Rust
fn index(req: HttpRequest) -> impl Responder {
    "Hello from the index page"
}

fn hello(path: Path<String>) -> impl Responder {
    format!("Hello {}!", *path)
}

fn main() {
    App::new()
        .resource("/", |r| r.method(Method::Get).with(index))
        .resource("/hello/{name}", |r| r.method(Method::Get).with(hello))
        .finish();
}
```


## Middleware - CORS

```Rust
let app = App::new().configure(|app| {
    Cors::for_app(app) // <- Construct CORS middleware builder
        .allowed_origin("https://www.rust-lang.org/")
        .allowed_methods(vec!["GET", "POST"])
        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
        .allowed_header(http::header::CONTENT_TYPE)
        .max_age(3600)
        .resource(/* ... */)
        .register()
});
```

## Middleware - CORS (allow from all)

```Rust
let app = App::new().configure(|app| {
    Cors::for_app(app) // <- Construct CORS middleware builder
        .send_wildcard()
        .allowed_methods(vec![Method::GET])
        .resource(/* ... */)
        .register()
});
```

## Middleware - CSRF

```Rust
let app = App::new()
    .middleware(
        csrf::CsrfFilter::new().allowed_origin("https://www.example.com"),
    )
    .resource("/", |r| {

```

Origin Header based.

## Middleware - User Sessions

```Rust
fn index(req: HttpRequest) -> Result<&'static str> {
    // access session data
    if let Some(count) = req.session().get::<i32>("counter")? {
        println!("SESSION value: {}", count);
        req.session().set("counter", count+1)?;
    } else {
        req.session().set("counter", 1)?;
    }

    Ok("Welcome!")
}
```
---

```Rust
fn main() {
    actix::System::run(|| {
        server::new(
          || App::new().middleware(
              SessionStorage::new(          // <- create session middleware
                CookieSessionBackend::signed(&[0; 32]) // <- create signed cookie session backend
                    .secure(false)
             )))
            .bind("127.0.0.1:59880").unwrap()
            .start();
    });
}

```

* Built-in: Session Cookie
* Other implementations must implement `SessionBackend`

## Middleware - Identity handling

```Rust
fn index(req: HttpRequest) -> Result<String> {
    // access request identity
    if let Some(id) = req.identity() {
        Ok(format!("Welcome! {}", id))
    } else {
        Ok("Welcome Anonymous!".to_owned())
    }
}

fn login(mut req: HttpRequest) -> HttpResponse {
    req.remember("User1".to_owned()); // <- remember identity
    HttpResponse::Ok().finish()
}

fn logout(mut req: HttpRequest) -> HttpResponse {
    req.forget(); // <- remove identity
    HttpResponse::Ok().finish()
}
```
---

```Rust
fn main() {
    let app = App::new().middleware(IdentityService::new(
        // <- create identity middleware
        CookieIdentityPolicy::new(&[0; 32])    // <- create cookie session backend
              .name("auth-cookie")
              .secure(false),
    ));
}
```

* Built-in: Cookie based identity
* Other implementations must implement `RequestIdentity`

## Static file handler

```Rust
use actix_web::{fs, App};

fn main() {
    let app = App::new()
        .handler("/static", fs::StaticFiles::new("."))
        .finish();
}
```

## Testing support

```Rust
fn index(req: HttpRequest) -> HttpResponse {
    if let Some(hdr) = req.headers().get(header::CONTENT_TYPE) {
        HttpResponse::Ok().into()
    } else {
        HttpResponse::BadRequest().into()
    }
}

fn main() {
    let resp = TestRequest::with_header("content-type", "text/plain")
        .run(index)
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = TestRequest::default().run(index).unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
```


## HTTP Client API

```Rust
use actix_web::client;

fn main() {
    tokio::run({
        client::get("http://www.rust-lang.org")   // Create request builder
            .header("User-Agent", "Actix-web")
            .finish().unwrap()
            .send()                               // Send http request
            .map_err(|_| ())                      // Error handling
            .and_then(|response| {                // server http response
                println!("Response: {:?}", response);
                Ok(())
            })
    });
}
```


# Benchmarks

## TechEmpower Web Framework Benchmark

Performance high-water marks for trivial exercises of framework functionality (routing, ORM, templates, etc.).

Real world apps will be substantially more complex with far lower RPS.

## JSON serialization

JSON serialization of a freshly-instantiated object.

```
{"message":"Hello, World!"}
```

---

![](images/bench1.png)

## Single query

Fetching a single row from a simple database table and serializing as a JSON response.

```
{"id":3217,"randomNumber":2149}
```

---

![](images/bench2.png)


## Multiple queries

Fetching multiple rows from a simple database table and serializing these rows as a JSON response.

The test is run multiple times: testing 1, 5, 10, 15, and 20 queries per request. All tests are run at 256 concurrency.

---

![](images/bench3.png)

## Fortunes

The framework's ORM is used to fetch all rows from a database table containing an unknown number of Unix fortune cookie messages. An additional fortune cookie message is inserted into the list at runtime and then the list is sorted by the message text. Finally, the list is delivered to the client using a server-side HTML template.

---

![](images/bench4.png)

## Data updates

Fetching multiple rows from a simple database table, converting the rows to in-memory objects, modifying one attribute of each object in memory, updating each associated row in the database individually, and then serializing the list of objects as a JSON response.

---

![](images/bench5.png)

## Plaintext

"Hello, World" message rendered as plain text.
```
Hello, World!
```

---

![](images/bench6.png)
