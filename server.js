

if (process.env.VC_TYPE === "issuer") {
    const { issuer } = require('./issuer/app.js')
    //issuer.listen(port, () => console.log(`Example issuer app listening on port ${port}!`))
    //issuer(app)

} 
else if (process.env.VC_TYPE === "verifier") {
 //   verifier(app)
 const { verifier } = require('./verifier/verifier.js')
 

} else {
    console.log("northing to run")
}
