"use strict";

var g_search = '';
var g_type = '';

var DesktopNotifications = {
/**
 * Checks if notifications are supported
 * @return {Boolean}
 */
isSupported:function() {
    return (Notification != 'undefined')
},
/**
 * ask use to display desktop notifications
 * @param callback
 */
requestPermission:function(callbck) {
    Notification.requestPermission(function() {
        if (typeof(callbck) == "function") {
            callbck(Notification.checkPermission() == 0);
        }
    });
},
/**
 * display a notification
 * @param img full path of image to be displayed e.g. http://somedomain.com/photo.jpg
 * @param notitification_title title of notification
 * @param notification_body body of nitification
 * @return {Boolean}
 */
doNotify:function(img,notification_title,notification_body) {
    // permission is ok
    if (!DesktopNotifications.isSupported()) { return false;}
    if (Notification.permission == 'default') {
        DesktopNotifications.requestPermission(function(f) { f();});
    }
    if (Notification.permission == 'granted') {
        var options = {};
        options['body'] = notification_body;
        if (img) { options['image'] = img;}
        var n  = new Notification(notification_title, options);
        return true;
    }
    return false;
}
};

var ssh_count = -1;
var apache_count = -1;
var nntp_proxy_count = -1;
function handle_request(search, type)
{
    g_search = search;
    g_type = type;
    var host = $("#host_selector").find(":selected").val()
    let {period, from, to} = get_period()
    $('#itemstable').html('');
    $.ajax({
        url: script_root + '/notifications_data/',
        type: 'POST',
        data: JSON.stringify({ 'period': period, 'to': to, 'from':from, 'search': search, 'host': host, 'type': type}),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        $('#itemstable').html(res.rhtml);
        document.title = ("Log Analyser - Notifications: " + res.title_type + " " + period).replace("_", " ");
        $("#header").text((res.title_type + ": " + period).replace("_", " "));
        set_ip_click_handler();
        ssh_count = -1;
        apache_count = -1;
        nntp_proxy_count = -1;
        load_notification_count();
    });
    return false;
}


function load_notification_count()
{
    let {period, from, to} = get_period();
    $.ajax({
        url: script_root + '/notifications_count/',
        type: 'POST',
        data: JSON.stringify({ 'period': period, 'to': to, 'from':from}),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
        var ssh = res['counts']['ssh'];
        var apache = res['counts']['apache'];
        var nntp_proxy = res['counts']['nntp_proxy'];
        $("#ssh_notification_count").text(ssh);
        $("#apache_notification_count").text(apache);
        $("#nntp_proxy_notification_count").text(nntp_proxy);
        if (ssh == 0) {
            $("#ssh_notification_count").addClass('bg-success');
            $("#ssh_notification_count").removeClass('bg-danger');
        } else {
            $("#ssh_notification_count").removeClass('bg-success');
            $("#ssh_notification_count").addClass('bg-danger');
        }
        if (apache == 0) {
            $("#apache_notification_count").addClass('bg-success');
            $("#apache_notification_count").removeClass('bg-danger');
        } else {
            $("#apache_notification_count").removeClass('bg-success');
            $("#apache_notification_count").addClass('bg-danger');
        }
        if (nntp_proxy == 0) {
            $("#nntp_proxy_notification_count").addClass('bg-success');
            $("#nntp_proxy_notification_count").removeClass('bg-danger');
        } else {
            $("#nntp_proxy_notification_count").removeClass('bg-success');
            $("#nntp_proxy_notification_count").addClass('bg-danger');
        }
        if (ssh > ssh_count && ssh_count >=0 ) {
            DesktopNotifications.doNotify(null,"New SSH login notification")
        } else if (apache > apache_count  && apache_count >= 0) {
            DesktopNotifications.doNotify(null,"New Apache notification")
        } else if (nntp_proxy > nntp_proxy_count  && nntp_proxy_count >= 0) {
            DesktopNotifications.doNotify(null,"New NNTP  proxy notification")
        }
        ssh_count = ssh;
        apache_count = apache;
        nntp_proxy_count = nntp_proxy;
    });
    return false;
}


$( document ).ready(function() {
    set_hosts();
    $('.dropdown-toggle').dropdown()
    $('body').css('background-image', 'url("' + script_root + '/static/img/necronomicon.png")');
    $('body').css('background-size', 'contain');
    $('#itemstablediv').scrollTop(0);
    $("[data-type^='apache']").click(function(event) { handle_request(  $("#searchbar").val(),'apache') });
    $("[data-type^='ssh']").click(function(event) { handle_request(  $("#searchbar").val(), 'ssh') });
    $("[data-type^='nntp_proxy']").click(function(event) { handle_request(  $("#searchbar").val(), 'nntp_proxy') });
    $("[name^='timeperiod").click(function(event) {
        if ($(this).attr('id') != 'custom')  {
             handle_request( g_search, g_type);
        }
    });

    $("#submit_custom").click(function() {
        $("#custom").prop("checked", true);
        $('#custom').dropdown('toggle');
        handle_request(g_search, g_type);
    });

    $("#custom").click(function() {
        $("#custom").prop("checked", true);
    });
    handle_request('', 'ssh');
    load_notification_count();
    setInterval(load_notification_count, 5000);
});