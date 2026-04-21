const API = "/api";
const TOKEN_KEY= "pg_token";

export function getToken(){
    return localStorage.getItem(TOKEN_KEY)|| "";

}

export function setToken(t){
    localStorage.setItem(TOKEN_KEY, t);
}

export function clearToken(){
    localStorage.removeItem(TOKEN_KEY);
}

export async function apiFetch(path, opts={}) {

    const headers = opts.headers || {};
    const tokenS = getToken();

    if (tokenS) headers["Authorization"]= `Bearer ${tokenS}`;

    const res = await fetch(`${API}${path}`, {...opts, headers });
    const Text= await res.text();
    let data =null;

    try {
        data =Text ? JSON.parse(Text): null;
    }
    catch{ 
        data= Text;
    }

    if(!res.ok){
        const message= (data && data.detail)? data.detail : (typeof data == "string"? data: "Request failed");
        throw new Error(message);
    }
    return data;
}

export async function requireAuthOrRedirect() {
    const tokenS= getToken();

    if(!tokenS) {
        location.href="/login.html";
        return null;
    }
    try{
        const me= await apiFetch("/auth/out")
        return me;
    }
    catch(e){
        clearToken();
        location.href= "/login.html";
        return null;
    }
    
}

export function qs(name){
    return new URLSearchParams(location.search).get(name)|| "";
}

export function escapeHtml(value){
    return String(value ?? "")
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#39;")
        
}

export async function downloadFromApi(path, filenameFallback){
    const tokenS = getToken();
    const headers = {};

    if (tokenS) headers["Authorization"] = `Bearer ${tokenS}`;

    const response = await fetch(`${API}${path}`,{headers});

    if(!response.ok){
        const text =await response.text();
        throw new Error(text || "Download failed");

    }

    const blob =await response.blob();
    const url = URL.createObjectURL(blob);
    const link=document.createElement("a");

    link.href =url;
    link.download = filenameFallback || "download";
    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}