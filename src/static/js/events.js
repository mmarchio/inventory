registerFormSubmit("submit");

if (document.getElementById("login_submit") != null) {
    document.getElementById("login_submit").addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        form = gebt("form");
        submitForm(form[0].id)
    });
}

function registerFormSubmit(id) {
    if (document.getElementById(id) != null) {
        document.getElementById(id).addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            form = gebt("form");
            submitForm(form[0].id, form[0].dataset.token)
        });
    }
}

if (document.getElementsByTagName("a").length > 0) {
    let elems = document.getElementsByTagName("a");
    for (let i=0; i<elems.length; i++) {
        elems[i].addEventListener("click", (e) => {
            e.preventDefault()
            e.stopPropagation()
            url = elems[i].href;
            headers = {
                "AUTHORIZATION": "Bearer " + elems[i].dataset.token
            };
            getPage(url, headers);
            let newState = {
                page: elems[i].dataset.page
            };
            let newTitle = elems[i].dataset.title;
            window.history.pushState(newState, newTitle, url);
        })
    }
}

async function getPage(url, headers) {
    if (url === "/logout") {
        url = "/"
    }
    try {
        const response = await fetch(url, {
          method: 'GET',
          headers: headers,
        });
    
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const responseText = await response.text();
        
         // Replace the current document with the fetched content
        document.open();
        document.write(responseText);
        document.close();
      } catch (error) {
        console.error("Error loading page:", error);
      }    
}


function registerRepeaterFormHandler(repeaterId, name, elemId, obj) {
    var id = repeaterId+"_"+name+"_"+elemId;
    document.getElementById(id).addEventListener("change", function(){
        if (document.getElementById(id).type === "checkbox") {
            if (document.getElementById(id).value === "1") {
                obj[name] = true;
            }
            if (document.getElementById(id).value === "0") {
                obj[name] = false;
            }
        } else {
            obj[name] = document.getElementById(id).value;
        }
    });
}

function registerRemoveEventHandler(repeaterId, elemId) {
    document.getElementById("remove_"+repeaterId+"_"+elemId).addEventListener("click", function(){
        var form = [];
        for (var i=0; i<document.form[repeaterId].length; i++) {
            if (document.form[repeaterId][i].id === elemId) {
                continue;
            }
            form[form.length] = document.form[repeaterId][i];
        }
        document.form[repeaterId] = form;
    });
}

