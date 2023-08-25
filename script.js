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
const REGEX_DOMAIN = /\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b/
const REGEX_IP = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
const REGEX_HASH_MD5 = ""
const REGEX_HASH_SHA1 = "//"
const REGEX_HASH_SHA256 = "//"

// Builds a URL to search for the artifactValue based on the artifactType
const buildUrl = (artifactType, artifactValue) => {
    const baseURLs = ARTIFACTS[artifactType]
    const searchPaths = PATHS[artifactType]

    for (let i=0; i<baseURLs.length; i++) {
        let base = baseURLs[i]
        let path = searchPaths[i]
        console.log(`${base}${path}${artifactValue}`)
    }
}

const checkRegex = (selected) => {
    
    const isDomain = REGEX_DOMAIN.test(selected)
    const isIP = REGEX_IP.test(selected)

    // console.log(`isDomain: ${isDomain}`)
    // console.log(`isIP: ${isIP}`)
    return {
        isDomain,
        isIP
    }
}

const testDomain = "test2.com"
const testIP = "142.250.81.238"
const testHashMD5 = "dba3e6449e97d4e3df64527ef7012a10"
const testHashSHA1 = "f66a592d23067c6eff15356f874e5b61ea4df4b5"
const testHashSHA256 = "e0c662d10b852b23f2d8a240afc82a72b099519fa71cddf9d5d0f0be08169b6e"

const result = checkRegex(testIP)

console.log(result)

buildUrl("ip", testIP)