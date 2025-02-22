document.repeater = {
    repeaters:[]
}
document.form = {}

registerRepeater("project");
registerRepeater("title");
registerRepeater("contact");

// function add(prefix, id) {
//     html = "<li id=\""+prefix+"_"+id+"\">";
//     html += "<ul>";
//     if (prefix === "project") {
//         html += input(prefix, "name", "text", id);
//         html += input(prefix, "url", "text", id);
//         html += input(prefix, "description", "text", id);
//     }
//     if (prefix === "title") {
//         html += input(prefix, "name", "text", id);
//         html += input(prefix, "from", "date", id);
//         html += input(prefix, "to", "date", id);
//     }
//     if (prefix === "contact") {
//         html += input(prefix, "type", "text", id);
//         html += input(prefix, "name", "text", id);
//         html += input(prefix, "relation", "text", id);
//         html += input(prefix, "title", "text", id);
//         html += input(prefix, "email", "text", id);
//         html += input(prefix, "phone", "text", id);
//     }
//     html += "<li><input type=\"button\" id=\"remove_"+prefix+"_"+id+"\" value=\"Remove\"></li>";
//     html += "</ul>";
//     html += "</li>";
    
//     return html;
// }

function add(prefix, name) {
    id=document.getElementById("new_"+prefix).dataset.room_count;
    document.getElementById(prefix+"_container").insertAdjacentElement("afterend", input(prefix, name, "text", id))
}

function remove(id) {
    var elem = document.getElementById(id);
    elem.parentNode.removeChild(elem);
}

function input(prefix, name, type, id) {
    html = `<li>
        <label for="`+prefix+`_`+id+`">`+name+`</label>
        <input type="`+type+`" id="`+prefix+`_`+id+` name="`+name+`-`+id+`">
        <input type="button" id="remove_`+prefix+`_`+id+`>Remove `+name+`</button></li>`;
    return html;
}

function registerRepeater(prefix) {
    document.getElementById("new_"+prefix).addEventListener("click", function(){
        document.getElementById(prefix+"s").insertAdjacentHTML("afterend", add(prefix, id));
        document.getElementById("remove_"+prefix+"_"+id).addEventListener("click", function(e){
            id = e.target.id.split("_");
            remove(prefix+"_"+id[2]);
        });
        document.repeater.repeaters[prefix].c++;
    })
}