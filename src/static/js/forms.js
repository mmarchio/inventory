async function submitForm(id, token) {
    data = {};
    inputs = document.getElementsByTagName("input");
    for (let i =0; i<inputs.length; i++) {
      data[inputs[i].id] = inputs[i].value;
    }
    selects = document.getElementsByTagName("select");
    for (let i=0; i<selects.length; i++) {
      data[selects[i].id] = selects[i].value;
    }
    switch (id) {
        case "create_user":
          sendForm("/api/user/create", data, token);
        break;
        case "create_location":
          sendForm("/api/content/location/create", data, token);
        break;
        case "create_policy":
          sendForm("/api/policy/create", data, token);
        break;
        case "login":
          const resp = await sendForm("/api/login", data);
          if ("authenticated" in resp && resp.authenticated) {
            const customHeaders = {
              "AUTHORIZATION": "Bearer " + resp.token
            };
            reloadWithHeaders(customHeaders);
          }
        break;

    }

}

async function sendForm(uri, data, token) {
    const rawResponse = await fetch(uri, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        "AUTHORIZATION": 'Bearer '+token,
      },
      body: JSON.stringify(data)
    });
    const content = await rawResponse.json()
    return content;
}

async function reloadWithHeaders(headers) {
  try {
    const response = await fetch("/dashboard", {
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
    console.error("Error reloading page:", error);
    // Fallback to a regular reload if fetch fails
     //window.location.reload();
  }
}
