/*
 * ghost-nm-plugin.c — NetworkManager VPN editor plugin for GHOST VPN.
 *
 * Implements NMVpnEditorPlugin (loaded by nm-connection-editor via dlopen)
 * and NMVpnEditor (the GTK3 form widget shown inside the editor).
 *
 * Build:
 *   make -C nm-plugin-gtk
 */

#include <stdio.h>
#include <string.h>
#include <gtk/gtk.h>
#include <NetworkManager.h>

#define GHOST_SERVICE "org.freedesktop.NetworkManager.ghost"

/* ═══════════════════════════════════════════════════════════════════════════
 * GhostEditor — implements NMVpnEditor
 * ═══════════════════════════════════════════════════════════════════════════*/

#define GHOST_TYPE_EDITOR (ghost_editor_get_type())
G_DECLARE_FINAL_TYPE(GhostEditor, ghost_editor, GHOST, EDITOR, GObject)

struct _GhostEditor {
    GObject    parent;
    GtkWidget *widget;      /* top-level GtkGrid returned to nm-connection-editor */

    /* required fields */
    GtkWidget *server_addr;
    GtkWidget *server_pub_key;
    GtkWidget *private_key;
    GtkWidget *tun_addr;

    /* optional fields */
    GtkWidget *sni;
    GtkWidget *front_host;
    GtkWidget *fingerprint;     /* GtkComboBoxText */
    GtkWidget *tun_name;
    GtkWidget *tun_mtu;         /* GtkSpinButton */
    GtkWidget *dns;
    GtkWidget *conn_lifetime;   /* GtkSpinButton */
};

static void ghost_editor_iface_init(NMVpnEditorInterface *iface);

G_DEFINE_TYPE_WITH_CODE(GhostEditor, ghost_editor, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR, ghost_editor_iface_init))

/* ── Layout helpers ───────────────────────────────────────────────────────*/

static GtkWidget *
make_entry(gboolean secret)
{
    GtkWidget *e = gtk_entry_new();
    gtk_entry_set_width_chars(GTK_ENTRY(e), 42);
    if (secret) {
        gtk_entry_set_visibility(GTK_ENTRY(e), FALSE);
        gtk_entry_set_input_purpose(GTK_ENTRY(e), GTK_INPUT_PURPOSE_PASSWORD);
        gtk_entry_set_icon_from_icon_name(GTK_ENTRY(e),
            GTK_ENTRY_ICON_SECONDARY, "view-conceal-symbolic");
        gtk_entry_set_icon_activatable(GTK_ENTRY(e), GTK_ENTRY_ICON_SECONDARY, TRUE);
    }
    return e;
}

/* Toggle password visibility when the eye icon is clicked. */
static void
on_eye_icon_press(GtkEntry *entry, GtkEntryIconPosition pos,
                  GdkEvent *ev G_GNUC_UNUSED, gpointer ud G_GNUC_UNUSED)
{
    if (pos != GTK_ENTRY_ICON_SECONDARY)
        return;
    gboolean vis = gtk_entry_get_visibility(entry);
    gtk_entry_set_visibility(entry, !vis);
    gtk_entry_set_icon_from_icon_name(entry, GTK_ENTRY_ICON_SECONDARY,
        vis ? "view-reveal-symbolic" : "view-conceal-symbolic");
}

static GtkWidget *
add_row(GtkGrid *grid, int row, const char *label_text, GtkWidget *widget,
        const char *tooltip)
{
    GtkWidget *lbl = gtk_label_new(label_text);
    gtk_label_set_xalign(GTK_LABEL(lbl), 1.0);
    gtk_widget_set_halign(lbl, GTK_ALIGN_END);
    gtk_grid_attach(grid, lbl,    0, row, 1, 1);
    gtk_grid_attach(grid, widget, 1, row, 1, 1);
    gtk_widget_set_hexpand(widget, TRUE);
    if (tooltip) {
        gtk_widget_set_tooltip_text(lbl,    tooltip);
        gtk_widget_set_tooltip_text(widget, tooltip);
    }
    return widget;
}

static void
add_section_label(GtkGrid *grid, int row, const char *text)
{
    GtkWidget *lbl = gtk_label_new(NULL);
    char *markup = g_markup_printf_escaped("<b>%s</b>", text);
    gtk_label_set_markup(GTK_LABEL(lbl), markup);
    g_free(markup);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_widget_set_margin_top(lbl, 8);
    gtk_grid_attach(grid, lbl, 0, row, 2, 1);
}

/* ── Populate form from an existing NMConnection ──────────────────────── */

static void
editor_load(GhostEditor *self, NMConnection *conn)
{
    NMSettingVpn *s = conn ? nm_connection_get_setting_vpn(conn) : NULL;
    if (!s)
        return;

#define LOAD(field, key) \
    do { \
        const char *_v = nm_setting_vpn_get_data_item(s, key); \
        if (_v && *_v) gtk_entry_set_text(GTK_ENTRY(self->field), _v); \
    } while (0)

    LOAD(server_addr,    "server-addr");
    LOAD(server_pub_key, "server-public-key");
    LOAD(sni,            "sni");
    LOAD(front_host,     "front-host");
    LOAD(tun_addr,       "tun-addr");
    LOAD(tun_name,       "tun-name");
    LOAD(dns,            "dns");
#undef LOAD

    /* fingerprint combo */
    const char *fp = nm_setting_vpn_get_data_item(s, "fingerprint");
    if (fp) {
        if      (!g_strcmp0(fp, "firefox")) gtk_combo_box_set_active(GTK_COMBO_BOX(self->fingerprint), 1);
        else if (!g_strcmp0(fp, "safari"))  gtk_combo_box_set_active(GTK_COMBO_BOX(self->fingerprint), 2);
        else if (!g_strcmp0(fp, "random"))  gtk_combo_box_set_active(GTK_COMBO_BOX(self->fingerprint), 3);
        else                                gtk_combo_box_set_active(GTK_COMBO_BOX(self->fingerprint), 0);
    }

    /* numeric spinners */
    const char *mtu = nm_setting_vpn_get_data_item(s, "tun-mtu");
    if (mtu && *mtu)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->tun_mtu), atoi(mtu));

    const char *lt = nm_setting_vpn_get_data_item(s, "conn-lifetime-sec");
    if (lt && *lt)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->conn_lifetime), atoi(lt));

    /* secret — loaded from the keyring by NM, passed here */
    const char *pk = nm_setting_vpn_get_secret(s, "private-key");
    if (pk && *pk)
        gtk_entry_set_text(GTK_ENTRY(self->private_key), pk);
}

/* ── Emit NMVpnEditor::changed so nm-connection-editor enables Save ───── */

static void
on_widget_changed(GtkWidget *widget G_GNUC_UNUSED, gpointer user_data)
{
    g_signal_emit_by_name(NM_VPN_EDITOR(user_data), "changed");
}

static void
on_combo_changed(GtkComboBox *combo G_GNUC_UNUSED, gpointer user_data)
{
    g_signal_emit_by_name(NM_VPN_EDITOR(user_data), "changed");
}

static void
on_spin_changed(GtkSpinButton *spin G_GNUC_UNUSED, gpointer user_data)
{
    g_signal_emit_by_name(NM_VPN_EDITOR(user_data), "changed");
}

/* Connect all input widgets so that any user edit notifies NM. */
static void
editor_connect_signals(GhostEditor *self)
{
    const char *entry_sig = "changed";
    GtkWidget  *entries[] = {
        self->server_addr, self->server_pub_key, self->private_key,
        self->tun_addr,    self->sni,            self->front_host,
        self->tun_name,    self->dns,
    };
    for (gsize i = 0; i < G_N_ELEMENTS(entries); i++)
        g_signal_connect(entries[i], entry_sig, G_CALLBACK(on_widget_changed), self);

    g_signal_connect(self->fingerprint,   "changed", G_CALLBACK(on_combo_changed), self);
    g_signal_connect(self->tun_mtu,       "value-changed", G_CALLBACK(on_spin_changed), self);
    g_signal_connect(self->conn_lifetime, "value-changed", G_CALLBACK(on_spin_changed), self);
}

/* ── NMVpnEditor::get_widget ──────────────────────────────────────────── */

static GObject *
editor_get_widget(NMVpnEditor *iface)
{
    return G_OBJECT(GHOST_EDITOR(iface)->widget);
}

/* ── NMVpnEditor::update_connection ──────────────────────────────────── */

static gboolean
editor_update_connection(NMVpnEditor *iface, NMConnection *conn, GError **error)
{
    GhostEditor  *self = GHOST_EDITOR(iface);
    NMSettingVpn *s    = nm_connection_get_setting_vpn(conn);

    if (!s) {
        s = (NMSettingVpn *)nm_setting_vpn_new();
        nm_connection_add_setting(conn, NM_SETTING(s));
    }
    g_object_set(s, NM_SETTING_VPN_SERVICE_TYPE, GHOST_SERVICE, NULL);

    /* Validate required fields */
    const char *server_addr = gtk_entry_get_text(GTK_ENTRY(self->server_addr));
    if (!server_addr || !*server_addr) {
        g_set_error(error, NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    "Server address is required (e.g. vpn.example.com:443)");
        gtk_widget_grab_focus(self->server_addr);
        return FALSE;
    }

    const char *pubkey = gtk_entry_get_text(GTK_ENTRY(self->server_pub_key));
    if (!pubkey || !*pubkey) {
        g_set_error(error, NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    "Server public key is required");
        gtk_widget_grab_focus(self->server_pub_key);
        return FALSE;
    }

    const char *privkey = gtk_entry_get_text(GTK_ENTRY(self->private_key));
    if (!privkey || !*privkey) {
        g_set_error(error, NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    "Client private key is required");
        gtk_widget_grab_focus(self->private_key);
        return FALSE;
    }

    const char *tun_addr = gtk_entry_get_text(GTK_ENTRY(self->tun_addr));
    if (!tun_addr || !*tun_addr) {
        g_set_error(error, NM_CONNECTION_ERROR,
                    NM_CONNECTION_ERROR_INVALID_PROPERTY,
                    "TUN address is required (e.g. 10.7.0.2/24)");
        gtk_widget_grab_focus(self->tun_addr);
        return FALSE;
    }

    /* Write data items; remove if cleared */
#define SET_DATA(field, key) \
    do { \
        const char *_v = gtk_entry_get_text(GTK_ENTRY(self->field)); \
        if (_v && *_v) nm_setting_vpn_add_data_item(s, key, _v); \
        else           nm_setting_vpn_remove_data_item(s, key); \
    } while (0)

    SET_DATA(server_addr,    "server-addr");
    SET_DATA(server_pub_key, "server-public-key");
    SET_DATA(sni,            "sni");
    SET_DATA(front_host,     "front-host");
    SET_DATA(tun_addr,       "tun-addr");
    SET_DATA(dns,            "dns");
#undef SET_DATA

    /* TUN name — use default if empty */
    const char *tname = gtk_entry_get_text(GTK_ENTRY(self->tun_name));
    nm_setting_vpn_add_data_item(s, "tun-name", (tname && *tname) ? tname : "ghost0");

    /* Fingerprint */
    static const char *fps[] = { "chrome", "firefox", "safari", "random" };
    int fp_idx = gtk_combo_box_get_active(GTK_COMBO_BOX(self->fingerprint));
    if (fp_idx < 0 || fp_idx > 3) fp_idx = 0;
    nm_setting_vpn_add_data_item(s, "fingerprint", fps[fp_idx]);

    /* Numeric fields */
    char buf[32];
    snprintf(buf, sizeof buf, "%d",
             (int)gtk_spin_button_get_value(GTK_SPIN_BUTTON(self->tun_mtu)));
    nm_setting_vpn_add_data_item(s, "tun-mtu", buf);

    snprintf(buf, sizeof buf, "%d",
             (int)gtk_spin_button_get_value(GTK_SPIN_BUTTON(self->conn_lifetime)));
    nm_setting_vpn_add_data_item(s, "conn-lifetime-sec", buf);

    /* Secret — NM stores this in the keyring via its secret agent */
    nm_setting_vpn_add_secret(s, "private-key", privkey);

    return TRUE;
}

static void
ghost_editor_iface_init(NMVpnEditorInterface *iface)
{
    iface->get_widget        = editor_get_widget;
    iface->update_connection = editor_update_connection;
}

static void ghost_editor_class_init(GhostEditorClass *klass G_GNUC_UNUSED) {}
static void ghost_editor_init(GhostEditor *self G_GNUC_UNUSED) {}

/* ── Constructor ─────────────────────────────────────────────────────────*/

static GhostEditor *
ghost_editor_new(NMConnection *conn)
{
    GhostEditor *self = g_object_new(GHOST_TYPE_EDITOR, NULL);
    GtkGrid     *grid = GTK_GRID(gtk_grid_new());
    int          row  = 0;

    gtk_grid_set_row_spacing(grid, 6);
    gtk_grid_set_column_spacing(grid, 12);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);

    /* ── Required ───────────────────────────────────────────────────────── */
    add_section_label(grid, row++, "Required");

    self->server_addr = add_row(grid, row++,
        "Server (host:port):", make_entry(FALSE),
        "VPN server address, e.g. vpn.example.com:443");

    self->server_pub_key = add_row(grid, row++,
        "Server public key:", make_entry(FALSE),
        "Server Noise IK static public key (base64). From: ghost-tools keygen on server.");

    self->private_key = add_row(grid, row++,
        "Client private key:", make_entry(TRUE),
        "Your Noise IK private key (base64). From: ghost-tools keygen.");
    g_signal_connect(self->private_key, "icon-press",
                     G_CALLBACK(on_eye_icon_press), NULL);

    self->tun_addr = add_row(grid, row++,
        "TUN address (CIDR):", make_entry(FALSE),
        "IP address assigned to the tunnel interface, e.g. 10.7.0.2/24");

    /* ── Optional ───────────────────────────────────────────────────────── */
    add_section_label(grid, row++, "Optional");

    self->sni = add_row(grid, row++,
        "SNI override:", make_entry(FALSE),
        "TLS SNI hostname. Defaults to host part of server address.");

    self->front_host = add_row(grid, row++,
        "Front host (CDN):", make_entry(FALSE),
        "HTTP/2 Host header for domain fronting via CDN (e.g. Cloudflare).");

    /* Fingerprint combo */
    GtkWidget *fp = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(fp), "Chrome");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(fp), "Firefox");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(fp), "Safari");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(fp), "Random");
    gtk_combo_box_set_active(GTK_COMBO_BOX(fp), 0);
    self->fingerprint = add_row(grid, row++,
        "TLS fingerprint:", fp,
        "Browser TLS fingerprint to mimic (uTLS).");

    self->tun_name = add_row(grid, row++,
        "TUN device name:", make_entry(FALSE),
        "Linux TUN interface name. Default: ghost0");
    gtk_entry_set_placeholder_text(GTK_ENTRY(self->tun_name), "ghost0");

    GtkWidget *mtu_spin = gtk_spin_button_new_with_range(576, 9000, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(mtu_spin), 1400);
    self->tun_mtu = add_row(grid, row++,
        "TUN MTU:", mtu_spin,
        "MTU for the tunnel interface. Default: 1400.");

    self->dns = add_row(grid, row++,
        "DNS servers:", make_entry(FALSE),
        "Comma-separated DNS server IPs routed through the tunnel, e.g. 1.1.1.1,8.8.8.8");
    gtk_entry_set_placeholder_text(GTK_ENTRY(self->dns), "1.1.1.1,8.8.8.8  (optional)");

    GtkWidget *lt_spin = gtk_spin_button_new_with_range(0, 3600, 10);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(lt_spin), 90);
    self->conn_lifetime = add_row(grid, row++,
        "Conn. lifetime (s):", lt_spin,
        "TCP connection rotation interval. 0 = disabled. Default: 90 s.");

    self->widget = GTK_WIDGET(grid);
    gtk_widget_show_all(self->widget);

    editor_load(self, conn);

    /* Connect after load so initial population doesn't fire spurious signals. */
    editor_connect_signals(self);

    return self;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GhostPlugin — implements NMVpnEditorPlugin
 * ═══════════════════════════════════════════════════════════════════════════*/

#define GHOST_TYPE_PLUGIN (ghost_plugin_get_type())
G_DECLARE_FINAL_TYPE(GhostPlugin, ghost_plugin, GHOST, PLUGIN, GObject)

struct _GhostPlugin { GObject parent; };

static void ghost_plugin_iface_init(NMVpnEditorPluginInterface *iface);

G_DEFINE_TYPE_WITH_CODE(GhostPlugin, ghost_plugin, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN, ghost_plugin_iface_init))

enum { PROP_0, PROP_NAME, PROP_DESC, PROP_SERVICE };

static void
ghost_plugin_get_property(GObject *obj, guint id, GValue *val, GParamSpec *pspec)
{
    switch (id) {
    case PROP_NAME:
        g_value_set_string(val, "Ghost VPN");
        break;
    case PROP_DESC:
        g_value_set_string(val,
            "DPI-resistant VPN over HTTPS/HTTP2 with Noise IK auth");
        break;
    case PROP_SERVICE:
        g_value_set_string(val, GHOST_SERVICE);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, id, pspec);
    }
}

static NMVpnEditor *
plugin_get_editor(NMVpnEditorPlugin *iface G_GNUC_UNUSED,
                  NMConnection *conn, GError **error G_GNUC_UNUSED)
{
    return NM_VPN_EDITOR(ghost_editor_new(conn));
}

static NMVpnEditorPluginCapability
plugin_get_capabilities(NMVpnEditorPlugin *iface G_GNUC_UNUSED)
{
    return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static void
ghost_plugin_iface_init(NMVpnEditorPluginInterface *iface)
{
    iface->get_editor       = plugin_get_editor;
    iface->get_capabilities = plugin_get_capabilities;
}

static void
ghost_plugin_class_init(GhostPluginClass *klass)
{
    GObjectClass *oc = G_OBJECT_CLASS(klass);
    oc->get_property = ghost_plugin_get_property;
    g_object_class_override_property(oc, PROP_NAME,    NM_VPN_EDITOR_PLUGIN_NAME);
    g_object_class_override_property(oc, PROP_DESC,    NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
    g_object_class_override_property(oc, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void ghost_plugin_init(GhostPlugin *self G_GNUC_UNUSED) {}

/* ── Module entry point — called by nm-connection-editor via dlopen ───── */

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory(GError **error G_GNUC_UNUSED)
{
    return g_object_new(GHOST_TYPE_PLUGIN, NULL);
}
