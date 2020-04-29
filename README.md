<h1 align="center">
  <br>
  <a href="https://hypercall.net"><img src="https://i.imgur.com/9vQOK3e.png" alt="logo" width="200"></a>
  <br>
  Gepard Bypass 
  <br>
</h1>

<h4 align="center">A way to get rid of Gepard</h4>

## The Gepard anti-cheat

The gepard anti-cheat is made of one dll which hooks windows APIs and blocks loading of dlls through a TLS callback. The special feature of this anti-cheat was the additional packet encryption for game developers.

## The bypass

In order to break through the anti-cheat, the various hooks are getting removed and the TLS callback gets nopped. The send-recv packets are displayed through an extra allocated console.

## Compiling

To compile the bypass you need [Visual Studio](https://www.visualstudio.com).

## License

*Gepard* is licensed under MIT, which means you can freely distribute and/or modify the source of *Gepard*.



