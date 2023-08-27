let DEFAULTS = {
    "domain": [
        "https://virustotal.com/gui/search/", 
        "https://talosintelligence.com/reputation_center/lookup?search=",
        "https://exchange.xforce.ibmcloud.com/url/",
        "https://www.abuseipdb.com/check/",
        "https://otx.alienvault.com/indicator/domain/"
    ],
    "ip": [
        "https://virustotal.com/gui/search/", 
        "https://talosintelligence.com/reputation_center/lookup?search=", 
        "https://exchange.xforce.ibmcloud.com/url/",
        "https://ipinfo.io/",
        "https://www.abuseipdb.com/check/",
        "https://otx.alienvault.com/indicator/ip/"
        // Add Spur
    ],
    "hash": [
        "https://virustotal.com/gui/search/",
        "https://exchange.xforce.ibmcloud.com/malware/",
        "https://www.hybrid-analysis.com/search?query=",
        "https://otx.alienvault.com/indicator/file/",
    ],
}



// Create a list item element for a single url and append it to the supplied type's list
const addToList = (typeID, url, idx) => {
    const del = document.createElement('button')
    del.type = "button"
    del.name = `delete-${idx}-${typeID.split('-')[1]}`
    del.id = `del-btn-${idx}`
    del.textContent = "X"
    del.className = "del-btn"
    del.onclick = handleDeleteSource

    const pre = document.createElement('pre')
    pre.textContent = url

    const li = document.createElement('li')
    li.appendChild(pre)
    li.appendChild(del)

    document.getElementById(typeID).appendChild(li)
}

const displaySettings = () => {
    chrome.storage.sync.get('osinterSettings', (settings) => {
        console.log("Settings:\n", settings)

        // If there are no stored settings, store the defaults
        if (Object.keys(settings).length === 0) { 
            chrome.storage.sync.set({"osinterSettings": DEFAULTS}, (newSettings) => {
                // location.reload()
                console.log("New Settings:", newSettings)
            })
        } else {
            // Display the loaded settings
            const types = settings['osinterSettings']

            console.log("TYPES:", types)

            let domains = types.domain
            let ips = types.ip
            let hashes = types.hash
            
            for (let [idx, url] of domains.entries()) {
                addToList('url-domain-list', url, idx)
            }
            for (let [idx, url] of ips.entries()) {
                addToList('url-ip-list', url, idx)
            }
            for (let [idx, url] of hashes.entries()) {
                addToList('url-hash-list', url, idx)
            }
        }
    })


}

// Extracts the new sources added after pressing the + button
const getNewSources = () => {
    let domains = document.getElementsByName("url-domain")
    let ips = document.getElementsByName("url-ip")
    let hashes = document.getElementsByName("url-hash")
    console.log(domains)
    return {
        "domains": domains,
        "ips": ips,
        "hashes": hashes
    }
}

// Combines the current sources with the newly added sources
const addNewSources = (settings, newSources) => {

    console.log("domains: ", settings)

    newSources.domains.forEach((s) => {
        console.log(s.value)
        if (s.value !== "") {
            settings.domain.push(s.value)
        }
    })
    newSources.ips.forEach((s) => {
        console.log(s.value)
        if (s.value !== "") {
            settings.ip.push(s.value)
        }
    })
    newSources.hashes.forEach((s) => {
        console.log(s.value)
        if (s.value !== "") {
            settings.hash.push(s.value)
        }
    })

    return settings
}

// Deletes all list itmes containing 'kill' in their class name for each type list
const deleteSources = (settings) => {
    let newSettings = settings.osinterSettings
    const sourcesToKill = document.getElementsByClassName('kill')
    console.log("Killing:", sourcesToKill)
    let delIdx = 0
    let type = ''
    for (source of sourcesToKill) {
        type = source.className.split(' ')[2]
        delIdx = newSettings[type].indexOf(source.className)
        newSettings[type].splice(delIdx, 1)
    }
    return newSettings
}

// Persists the settings to chrome.storage.sync
const storeSettings = () => {
    chrome.storage.sync.get('osinterSettings', (settings) => {
        console.log("Settings before store:\n", settings)

        // If there are no stored settings, store the defaults
        if (Object.keys(settings).length === 0) { 
            chrome.storage.sync.set({ "osinterSettings": DEFAULTS}, (newSettings) => {
                console.log("New Settings:", newSettings)
            })
        } else { // Append the new sources to each artifact type's list
            console.log("Saving")
            let settingsAfterDelete = deleteSources(settings) // remvove any deleted sources
            const newSources = getNewSources() // collect any new sources
            let newSettings = addNewSources(settingsAfterDelete, newSources) // combine all updates
            console.log("New Settings-raw:", newSettings.osinterSettings)

            chrome.storage.sync.set({ "osinterSettings": newSettings}, (settings) => {
            console.log("Old settings", settings)
            console.log("New Settings:", newSettings.osinterSettings)
            location.reload()
    })
        }
    })
    
}

// Create an input field that the user can input a new URL after hitting the add button
const addInputToList = (type) => {
    // Used to style the new li element in the type list
    let li = document.createElement('li')
    li.className = "new-li"

    // Used for entering in a new source URL
    let input = document.createElement('input')
    input.type = "text";
    input.name = `url-${type}`
    input.placeholder = `Enter new ${type} source`
    li.appendChild(input) // Make the input a child of the li element

    // Append the li element containing the input to the type list
    document.getElementById(`url-${type}-list`).appendChild(li) 
    
    console.log(`New ${type} added`)
}

// Determine which add button was clicked and add an input li element to that type's list 
const handleAddSource = (e) => {
    switch(e.target.id) {
        case "add-domain":
            addInputToList("domain")
            break
        case "add-ip":
            addInputToList("ip")
            break
        case "add-hash":
            addInputToList("hash")
            break
    }
}

// When a source is deleted, modify its class name to hide it, pass type and index for later processing
const handleDeleteSource = (e) => {
    console.log("Delete")
    const idx = e.target.name.split('-')[1]
    const type = e.target.name.split('-')[2]
    console.log(e)
    console.log(e.target.parentNode)
    e.target.parentNode.className += `kill ${idx} ${type}`
    e.target.name += `-kill-${idx}`
}

document.addEventListener('DOMContentLoaded', displaySettings)
document.getElementById('add-domain').addEventListener('click', handleAddSource)
document.getElementById('add-ip').addEventListener('click', handleAddSource)
document.getElementById('add-hash').addEventListener('click', handleAddSource)
document.getElementById('save-btn').addEventListener('click', storeSettings)

const deleteButtons = document.getElementById('del-btn')
if (deleteButtons !== null) {
    deleteButtons.addEventListener('click', handleDeleteSource)
}

