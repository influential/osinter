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
    const resultMap = { 0: "domain", 1: "ip", 2: "ip", 3: "hash", 4: "hash", 5: "hash" }
    result = findResult(resultList, resultMap)
    // console.log("results list: ", resultList)
    // console.log("result: ", result)

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
            // console.log("map[i]: ", map[i])
            result = map[i]
        }
    })
    return result
}

// Checks the results of the regex and checkIPv6 function to ensure there is only one match
const validateSingleMatch = (results) => {
    let seen = 0
    results.forEach((val) => { val === true ? seen += 1 : null })
    if (seen === 0) { return -2 }
    return seen>1 && seen>0 ? false : true
}

// Builds a URL to search for the artifactValue based on the artifactType (assumes valid type)
// Spawn a new window and a new tab for each url
const buildUrls = async (artifactType, artifactValue) => {
    let urls = []
    let url = ""
    let searchPath = ""
    let searchURLs = []

    await chrome.storage.sync.get('osinterSettings', (settings) => {
        const types = settings.osinterSettings
        // console.log(types)
        // console.log("artifactType: ", artifactType)
    
        searchURLs = types[artifactType]
    
        for (let i=0; i<searchURLs.length; i++) {
            searchPath = searchURLs[i]
            url = `${searchPath}${artifactValue}`
            urls.push(url)
        }
        // console.log("builtURLs: ", urls)
        chrome.windows.create({ focused: true, url: urls })
    })
    return urls
}

// Whenever osinter is chosen from context menu:
// validate selection, generate usable urls, spawn new window, spawn a tab for each url
const query = async (selected) => {
    const artifactType = checkSelectedText(selected) // Determine what kind of artifact the highlighted text is

    switch(artifactType) {
        case -1:
            console.log("Error: more than one artifact type matched")
            return -1
        case -2:
            console.log("No matches found, do nothing")
            return -2
        case undefined:
            console.log("Error: error parsing highlighted text")
            break
        default:
            console.log("Artifact Type: ", artifactType)
            break
      }

    const urls = await buildUrls(artifactType, selected)
    console.log("URLs: \n", urls)
}

// Listen for highlighted text, if found add osinter to context menu
chrome.runtime.onInstalled.addListener(async () => {
    chrome.contextMenus.create({
        id: "osinter",
        title: "Osinter",
        type: 'normal',
        contexts: ['selection'],
    });
});

// Listen for when osinter is selected from context menu
chrome.contextMenus.onClicked.addListener(async (item, tab) => {
    const selected = item.selectionText
    console.log("Checking: ", selected)
    await query(selected)   
});