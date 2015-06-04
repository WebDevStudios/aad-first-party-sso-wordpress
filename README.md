# Azure Active Directory First-Party Single Sign-on for WordPress

###**Please Note: This plugin is built with a very specific use-case in mind. This plugin will only work for First Party AAD logins from Microsoft. If you'd like to set this up on your site, you'll need to request and be granted access.**

---

A WordPress plugin that allows organizations to use their Azure Active Directory
user accounts to sign in to WordPress. Organizations with Office 365 already have
Azure Active Directory and can use this plugin for all of their users and any onsite
Active Directory linked to Azure Active Directory can also be used.

- Standard WordPress login is still available.

In the typical flow:

1. User attempts to access the admin section of the blog (`wp-admin`). At the sign in page, they are given a link to sign in with their Azure Active Directory organization account (e.g. an Office 365 account).
2. After signing in, the user is redirected back to the blog with a JSON Web Token (JWT), containing a minimal set of claims.
3. The plugin uses these claims to attempt to find a WordPress user with the Azure AD ID that matches the Azure Active Directory user.
4. If one is found, the user is authenticated in WordPress as that user.
5. (Optional) Membership to certain groups in Azure AD can be mapped to roles in WordPress.

## Getting Started

The following instructions will get you started. In this case, we will be configuring the plugin to use the user roles configured in WordPress.

### 1. Download the plugin

You can do this with `git` or with the 'Download ZIP' link on the right.

Place the `aad-sso-wordpress` folder in your WordPress' plugin folder. Normally, this is `<yourblog>/wp-content/plugins`.

### 2. Get your domain whitelisted by Microsoft domain services
Domain must have ssl enabled.

### 3. Configure the plugin

The plugin can be configured in Settings > AAD Settings.
