// Stores base URL's for each artifact type's sources
let ARTIFACTS = {
    "domain": [
        "https://virustotal.com/", 
        "https://talosintelligence.com/",
        "https://exchange.xforce.ibmcloud.com/",
        "https://www.abuseipdb.com/",
        "https://otx.alienvault.com/"
    ],
    "ip": [
        "https://virustotal.com/", 
        "https://talosintelligence.com/", 
        "https://exchange.xforce.ibmcloud.com/",
        "https://ipinfo.io/",
        "https://www.abuseipdb.com/",
        "https://otx.alienvault.com/"
        // Add Spur
    ],
    "hash": [
        "https://virustotal.com/",
        "https://talosintelligence.com/",
        "https://exchange.xforce.ibmcloud.com/",
        "https://www.hybrid-analysis.com/",
        "https://otx.alienvault.com/",
    ],
}

// Stores the URL paths for searching based on artifact type
// Each list is in the same order as the ARTIFACTS list
// Includes entire search path up to either an equals sign or forward slash 
// Assumes there is nothing after the input search artifact
let PATHS = {
    "domain": [
        "gui/domain/", 
        "reputation_center/lookup?search=",
        "url/",
        "check/",
        "indicator/domain/"
    ],
    "ip": [
        "gui/ip/",
        "reputation_center/lookup?search=",
        "ip/",
        "",
        "check/",
        "indicator/ip/"
    ],
    "hash": [
        "gui/file/",
        "reputation_center/lookup?search=",
        "malware/",
        "search?query=",
        "indicator/file/"
    ]
}

// TODO: allow custom regex that the user inputs, use these as default
const REGEX_DOMAIN = /^(?!([0-9]{1,3}\.){3}[0-9]{1,3}$)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})$/
const REGEX_IP = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
const REGEX_HASH_MD5 = /^[a-fA-F0-9]{32}$/
const REGEX_HASH_SHA1 = /^[a-fA-F0-9]{40}$/
const REGEX_HASH_SHA256 = /^[a-fA-F0-9]{64}$/
const REGEX_HEX = /^[0-9a-fA-F]+$/

// Referenced: https://www.geeksforgeeks.org/check-if-the-given-string-is-ipv4-or-ipv6-or-invalid/#
function checkIPv6(s) {
    if (!s.includes(":")) { return false }
    let numColons = s.split(':').length - 1; // Count the occurrence of ':' in the given string
    if (numColons !== 7) { return false } // Not a valid IP Address
   
    let octets = s.split(':'); // Split the string into octets
    if (octets.length !== 8) { return false } // there should always be 8 octets
   
    // Check if all the tokenized strings are in hexadecimal format
    for (let octet of octets) {
      if (!REGEX_HEX.test(octet) || octet.length > 4 || octet.length < 1) {  // Check if the octet string is a valid hexadecimal number
        return false
      }
    }
   
    return true
}

// Checks a given string and determines which artifact it is
// Returns the artifact type as a string (matches ARTIFACTS and PATHS key)
const checkSelectedText = (selected) => {
    const isDomain = REGEX_DOMAIN.test(selected)
    const isIPv4 = REGEX_IP.test(selected)
    const isIPv6 = checkIPv6(selected)
    const isMD5 = REGEX_HASH_MD5.test(selected)
    const isSHA1 = REGEX_HASH_SHA1.test(selected)
    const isSHA256 = REGEX_HASH_SHA256.test(selected)

    const resultList = [isDomain, isIPv4, isIPv6, isMD5, isSHA1, isSHA256]
    console.log("results list: ", resultList)
    const resultMap = { 0: "domain", 1: "ip", 2: "ip", 3: "hash", 4: "hash", 5: "hash" }
    result = findResult(resultList, resultMap)
    console.log("result: ", result)

    return result === -1 ? -1 : result  
}

// Check for only one match and return the matching artifact type as a usable key
const findResult = (results, map) => {
    let result = -1
    const matches = validateSingleMatch(results)
    if (matches === -1 || matches === -2) { return matches }

    results.forEach((outcome, i) => {
        if (i > results.length) { return -2 } // No matches were found
        if (outcome === true) {
            console.log("map[i]: ", map[i])
            result = map[i]
        }
    })
    return result
}

// Checks the results of the regex and checkIPv6 function to ensure there is only one match
const validateSingleMatch = (results) => {
    let seen = 0
    // results.forEach((val) => { if (val === true) { seen += 1 } })
    results.forEach((val) => { val === true ? seen += 1 : null })
    if (seen === 0) { return -2 }
    return seen>1 && seen>0 ? false : true
}

// Builds a URL to search for the artifactValue based on the artifactType (assumes valid type)
const buildUrls = (artifactType, artifactValue) => {
    const baseURLs = ARTIFACTS[artifactType]
    const searchPaths = PATHS[artifactType]
    let urls = []
    let url = ""
    let base = ""
    let path = ""

    for (let i=0; i<baseURLs.length; i++) {
        base = baseURLs[i]
        path = searchPaths[i]
        url = `${base}${path}${artifactValue}`
        urls.push(url)
        // console.log(url)
    }

    return urls
}

// Called on highlight events?
const query = (selected) => {
    console.log("Checking")
    const artifactType = checkSelectedText(selected) // Determine what kind of artifact the highlighted text is

    switch(artifactType) {
        case -1:
            console.log("Error: more than one artifact type matched")
            return
        case -2:
            console.log("No matches found, do not display in context menu")
            return
        case undefined:
            console.log("Error: error parsing highlighted text")
            break
        default:
            console.log("Found artifact type")
      }

    console.log("type: ", artifactType)
    const urls = buildUrls(artifactType, selected)
    console.log("URLs: \n", urls)
}

const testBadInput = "asdlkfjda;l"
const testDomain = "google.com"
const testIPv4 = "142.250.81.238"
const testIPv6 = "2001:db8:3333:4444:5555:6666:7777:8888"
const testHashMD5 = "dba3e6449e97d4e3df64527ef7012a10"
const testHashSHA1 = "f66a592d23067c6eff15356f874e5b61ea4df4b5"
const testHashSHA256 = "e0c662d10b852b23f2d8a240afc82a72b099519fa71cddf9d5d0f0be08169b6e"

const selected = testDomain // Highlighted text in the browser


query(selected)