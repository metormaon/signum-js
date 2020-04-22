class Signum {
    /*

    POST
Ensure referrer
Send x-Requested-With: XmlHttpRequest
Ensure Synchronizer Token
Ensure elapsed time
Send hashcash if was requested
Send captcha if was requested



The response may be a proof of work request, or the actual login.



     */

    /**
     * POST - to prevent CSRF
     * Referer should be sent automatically.
     * x-Requested-With: XmlHttpRequest - automatically
     * @param username
     * @param hashedPasstext
     * @param loginUrl
     * @param hashcash
     * @param serverInstructions
     * @param csrfToken
     * @returns {Promise<void>}
     */
    static async executeLogin(username: String, hashedPasstext: String, loginUrl: String, serverInstructions: JSON,
                              hashcash: String = "", csrfToken: String = "", ) {
        if (!username) {
            throw new Error("Username is null or empty");
        }

        if (!hashedPasstext) {
            throw new Error("Passtext is null or empty");
        }

        const userDetails = {
          username: username,
          hashedPasstext: hashedPasstext
        };

        const headers = {
            'Content-Type': 'application/json;charset=utf-8',
        };

        if (serverInstructions['hashcash']['require']
            && Signum.validateHashCash(hashcash, serverInstructions['hashcash']['zeroCount'])) {
            headers['x-hashcash'] = hashcash;
        }

        if (serverInstructions['csrf_token']['require']) {
            headers['x-csrf-token'] = csrfToken;
        }

        const response = await fetch(loginUrl, {
            method: 'POST',
            headers: headers,
            body: userDetails
        });

        const result = await response.json();
    }

    static validateHashCash(hashcash: String, zeroCount: number) {
        return false;
    }
}