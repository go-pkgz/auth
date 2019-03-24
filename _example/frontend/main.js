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

function loginAnonymously(username) {
	return fetch(
		`/auth/anonymous/login?id=auth-example&user=${encodeURIComponent(username)}`
	);
}

const validUsernameRegex = /^[a-zA-Z][\w ]+$/;

function getUsernameInvalidReason(username) {
	if (username.length < 3) return "Username must be at least 3 characters long";
	if (!validUsernameRegex.test(username))
		return "Username must start from the letter and contain only latin letters, numbers, underscores, and spaces";
	return null;
}

function getAnonymousLoginForm(onSubmit) {
	const form = document.createElement("form");

	const input = document.createElement("input");
	input.type = "text";
	input.placeholder = "Username";
	input.className = "anon-form__input";

	const submit = document.createElement("input");
	submit.type = "submit";
	submit.value = "Log in";
	submit.className = "anon-form__submit";

	const onValueChange = val => {
		const reason = getUsernameInvalidReason(val);
		if (reason === null) {
			submit.disabled = false;
			submit.title = "";
		} else {
			submit.disabled = true;
			submit.title = reason;
		}
	};

	onValueChange(input.value);

	input.addEventListener("input", e => {
		const val = e.target.value;
		const reason = getUsernameInvalidReason(val);
		if (reason === null) {
			submit.disabled = false;
			submit.title = "";
		} else {
			submit.disabled = true;
			submit.title = reason;
		}
	});

	form.appendChild(input);
	form.appendChild(submit);

	form.addEventListener("submit", e => {
		e.preventDefault();
		onSubmit(input.value);
	});

	return form;
}

function getLoginLinks() {
	return getProviders().then(providers =>
		providers.map(prov => {
			let a;
			if (prov === "anonymous") {
				a = document.createElement("span");
				a.dataset.provider = prov;
				a.className = "login__prov";

				const textEl = document.createElement("span");
				textEl.textContent = "Login with " + prov;
				textEl.className = "pseudo";
				a.appendChild(textEl);
				textEl.addEventListener("click", e => {
					form.style.display = form.style.display === "none" ? "block" : "none";
					form.querySelector(".anon-form__input").focus();
				});

				const form = getAnonymousLoginForm(username => {
					loginAnonymously(username)
						.then(() => {
							window.location.replace(window.location.href);
						})
						.catch(e => {
							const status = document.querySelector(".status__label");
							status.textContent = e.message;
						});
				});
				form.style.display = "none";
				form.className = "anon-form login__anon-form";

				a.appendChild(form);
			} else {
				a = document.createElement("span");
				a.dataset.provider = prov;
				a.textContent = "Login with " + prov;
				a.className = "pseudo login__prov";
				a.addEventListener("click", e => {
					e.preventDefault();
					login(prov)
						.then(() => {
							window.location.replace(window.location.href);
						})
						.catch(e => {
							const status = document.querySelector(".status__label");
							status.textContent = e.message;
						});
				});
			}
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
				window.location.replace(window.location.href);
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
		keytd.className = "info__key-cell";
		keytd.textContent = key;

		let valtd = document.createElement("td");
		valtd.className = "info__val-cell";
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

		req("/private_data")
			.then(data => {
				data = JSON.stringify(data, null, "  ");
				const el = document.createElement("pre");
				el.textContent = data;
				el.className = "protected-data__data";
				const container = document.querySelector(".protected-data");
				const placeholder = container.querySelector(
					".protected-data__placeholder"
				);
				placeholder.remove();
				container.appendChild(el);
			})
			.catch(e => console.error(e));
	});
}

main().catch(e => {
	console.error(e);
});
