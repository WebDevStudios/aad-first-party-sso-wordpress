# Azure Active Directory Single Sign-on for WordPress

A WordPress plugin that allows organizations to use their Azure Active Directory
user accounts to sign in to WordPress. Organizations with Office 365 already have
Azure Active Directory and can use this plugin for all of their users and any onsite
Active Directory linked to Azure Active Directory can also be used.

- Security group membership can be mapped to WordPress user roles.
- Standard WordPress login is still available.

In the typical flow:

1. User attempts to access the admin section of the blog (`wp-admin`). At the sign in page, they are given a link to sign in with their Azure Active Directory organization account (e.g. an Office 365 account).
2. After signing in, the user is redirected back to the blog with a JSON Web Token (JWT), containing a minimal set of claims.
3. The plugin uses these claims to attempt to find a WordPress user with an email address or login name that matches the Azure Active Directory user.
4. If one is found, the user is authenticated in WordPress as that user.
5. (Optional) Membership to certain groups in Azure AD can be mapped to roles in WordPress.

## Getting Started

The following instructions will get you started. In this case, we will be configuring the plugin to use the user roles configured in WordPress.

### 1. Download the plugin

You can do this with `git` or with the 'Download ZIP' link on the right.

Place the `aad-sso-wordpress` folder in your WordPress' plugin folder. Normally, this is `<yourblog>/wp-content/plugins`.

### 2. Register an Azure Active Directory application

For these steps, you must have an Azure subscription with access to the Azure Active Directory tenant that you would like to use with your blog.

1. Sign in to the [Azure portal](https://manage.windowsazure.com), and navigate to the ACTIVE DIRECTORY section. Choose the directory (tenant) that you would like to use. This should be the directory containing the users and (optionally) groups that will have access to your WordPress blog.
3. Under the APPLICATIONS tab, click ADD to register a new application. Choose 'Add an application my organization is developing', and a recognizable name. Choose values for sign-in URL and App ID URL. The blog's URL is usually a good choice.
4. When the app is created, under the CONFIGURE tab, generate a key and copy the secret value (it will be visible once only, after you save).
5. Add a reply URL with the format: `https://<your blog url>/wp-login.php`. 

### 3. Configure the plugin

The plugin can be configured in Settings > AAD Settings.

### 4. (Optional) Set WordPress roles based on Azure AD group membership

The AADSSO plugin can be configured to set different WordPress roles based on the user's membership to a set of user-defined groups. This is a great way to control who has access to the blog, and under what role.

The configuration is also done in Settings > AAD Settings

- Enable role mapping must be checked.
- Each role contains a key-value map of Azure Active Directory group object IDs (the keys) and WordPress roles (values). Valid values for roles are `'administrator'`, `'editor'`, `'author'`, `'contributor'`, `'subscriber'`.
- Custom WordPress roles to Activie Directory groups can be added in the Custom role mapping box by placing one mapping per line in the format: wp_role aad_group.

### Groups membership-based roles (no default role)

Users are matched by their login names in WordPress, and WordPress roles are dictated by membership to a given Azure AD group. If the user is not a part of any of these groups, they are assigned the `default new user role in WordPress.


