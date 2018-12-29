function getCookies() {
	return document.cookie.split("; ").reduce((c, x) => {
		const splitted = x.split("=");
		c[splitted[0]] = splitted[1];
		return c;
	}, {});
}

function req(endpoint, data = {}) {
	const cloneData = Object.assign({}, data);
	const cookies = getCookies();
	const token = cookies["XSRF-TOKEN"];

	if (cloneData.hasOwnProperty("headers")) {
		const headersClone = new Headers(cloneData.headers);
		cloneData.headers = headersClone;
	} else {
		cloneData.headers = new Headers();
	}

	if (token) {
		cloneData.headers.append("X-XSRF-TOKEN", token);
	}

	return fetch(endpoint, cloneData).then(resp => {
		if (resp.status >= 400) throw resp;
		return resp.json().catch(() => null);
	});
}

function getProviders() {
	return req("/auth/list");
}

function getUser() {
	return req("/auth/user").catch(e => {
		if (e.status && e.status === 401) return null;
		throw e;
	});
}

function login(prov) {
	return new Promise((resolve, reject) => {
		// try {
		// } catch (e) {
		// 	console.error(e);
		// }
		const url = window.location.href + "?close=true";
		const eurl = encodeURIComponent(url);
		const win = window.open(
			"/auth/" + prov + "/login?id=auth-example&from=" + eurl
		);
		const interval = setInterval(() => {
			try {
				if (win.closed) {
					reject(new Error("Login aborted"));
					clearInterval(interval);
					return;
				}
				if (win.location.search.indexOf("error") !== -1) {
					reject(new Error(win.location.search));
					win.close();
					clearInterval(interval);
					return;
				}
				if (win.location.href.indexOf(url) === 0) {
					resolve();
					win.close();
					clearInterval(interval);
					return;
				}
			} catch (e) {}
		}, 100);
	});
}

function getLoginLinks() {
	return getProviders().then(providers =>
		providers.map(prov => {
			const a = document.createElement("a");
			a.dataset.provider = prov;
			a.href = "#";
			a.textContent = "Login with " + prov;
			a.className = "login__prov";
			a.addEventListener("click", e => {
				e.preventDefault();
				login(prov)
					.then(() => {
						window.location.reload();
					})
					.catch(e => {
						const status = document.querySelector(".status__label");
						status.textContent = e.message;
					});
			});
			return a;
		})
	);
}

function getLogoutLink() {
	const a = document.createElement("a");
	a.href = "#";
	a.textContent = "Logout";
	a.className = "login__prov";
	a.addEventListener("click", e => {
		e.preventDefault();
		req("/auth/logout")
			.then(() => {
				window.location.reload();
			})
			.catch(e => console.error(e));
	});
	return a;
}

function getUserInfoFragment(user) {
	const table = document.createElement("table");
	table.className = "info__container";
	const imgtd = document.createElement("td");
	imgtd.rowSpan = Object.keys(user).length;
	imgtd.className = "info__image-wide";
	const img = document.createElement("img");
	img.class = "info__user-image";
	img.src = user.picture;
	imgtd.appendChild(img);

	{
		const imgtr = document.createElement("tr");
		imgtr.className = "info__image-narrow";
		table.appendChild(imgtr);
		const imgtd = document.createElement("td");
		imgtr.appendChild(imgtd);
		imgtd.colSpan = 3;
		const img = document.createElement("img");
		img.class = "info__user-image";
		img.src = user.picture;
		imgtd.appendChild(img);
	}

	let imgappended = false;
	for (let key of Object.keys(user)) {
		let tr = document.createElement("tr");
		if (!imgappended) {
			tr.appendChild(imgtd);
			imgappended = true;
		}
		let keytd = document.createElement("td");
		keytd.textContent = key;

		let valtd = document.createElement("td");
		if (typeof user[key] === "object") {
			valtd.textContent = JSON.stringify(user[key]);
		} else {
			valtd.textContent = user[key];
		}
		tr.appendChild(keytd);
		tr.appendChild(valtd);
		table.appendChild(tr);
	}
	return table;
}

function main() {
	if (window.location.search.indexOf("?close=true") !== -1) {
		document.body.textContent = "Logged in!";
		return;
	}
	return getUser().then(user => {
		const loginContainer = document.querySelector(".login");
		const statusElement = document.querySelector(".status__label");
		if (!user) {
			getLoginLinks().then(links => {
				for (let link of links) {
					loginContainer.appendChild(link);
				}
			});
			return;
		}
		loginContainer.appendChild(getLogoutLink());
		statusElement.textContent = "logged in as " + user.name;
		const infoEl = document.querySelector(".info");
		infoEl.textContent = "";
		infoEl.appendChild(getUserInfoFragment(user));
	});
}

main().catch(e => {
	console.error(e);
});
