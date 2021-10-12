"use strict";

var colours = [
'#d43d51',
'#dd584a',
'#e27147',
'#e48948',
'#bdc367',
'#e4a04e',
'#e3b75a',
'#e0cd6d',
'#9bb965',
'#7aae65',
'#5aa267',
'#38956a',
'#00876c',

//'#A2383B', '#c78200', '#2f6473', '#38A29F', '#277171', '#A23888', '#71275F','#A28D38',  '#F9F871',
//    '#FFC258', '#F38E56', '#A93D62', '#D6605D', '#364C6A', '#2F4858', '#4D4D78', '#8E4375', '#6D4A7C',
    ];

var g_name= '';
var g_type = '';
var g_search = '';
var max_datapoints = 120;

var simple_types = [
    "ssh_users",
    "ssh_ips",
    "apache_response",
    "apache_ips",
];
function round(nr, dig)
{
    if (dig == undefined) dig = 0
    var exp = 10 ** dig;
//    console.log( Math.round((nr+ Number.EPSILON) * exp)/exp);
    return Math.round((nr+ Number.EPSILON) * exp)/exp;
}


function calculate_height()
{
    var nb_height = $("#navbar").height();
    var b_height = $("body").height();
    var w_height = window.innerHeight;
    var res_height = Math.floor(w_height-nb_height);
//    console.log(w_height, nb_height, res_height, b_height);
    $('#maindiv').height(res_height);
}
function fmtChartJSPerso(n, p, fmt)
{
    if (fmt == "text") {
        if (p.length > 15) {
            var s =p;
            var l =p.length;
            return s.slice(0,5) + "..." + s.slice(l-5, l);
        }
        return p;
    } else if (fmt == 'number') {
        if (p < 1024) return p;
        if (p < 1024 * 1024 ) return (round(p / 1024, 1)).toString() + "K";
        if (p < 1024 * 1024 * 1024 ) return (round(p / (1024 * 1024), 1)).toString() + "M";
        if (p < 1024 * 1024  * 1024 * 1024 ) return  (round(p / (1024 * 1024 * 1024), 1 )).toString() + "G";
        if (p < 1024 * 1024  * 1024 * 1024  * 1024) return  (round(p / (1024 * 1024 * 1024  * 1024),1)).toString() + "T";
        return p;
    }
}

function load_graph(canvas_id, type, name, period, to,from, title, host)
{
    $.ajax({
        url: script_root + '/data/',
        type: 'POST',
        data:  JSON.stringify({'type': type, 'period': period, 'name': name, 'raw': true, 'to': to, 'from':from, 'host': host} ),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
        var res = JSON.parse(data);
//        console.log (res);
    var baroptions= {
            graphTitle: title,
            graphTitleFontSize: 16,
            canvasBorders: true,
            canvasBordersWidth: 1,
            animation : false,
            responsive: true,
            legend: false,
            highLight: true,
            fmtXLabel: "text",
            fmtYLabel:"number",
            rotateLabels: "smart",
            annotateLabel: "<%=v2+': '+v1+' '+v3%>",
            annotateDisplay: true,
            yAxisUnitFontSize: 16,
            inGraphDataShow : true,
            spaceBetweenBar : 4,
            scaleFontColor: "#ddd",
            graphTitleFontColor: "#bbb",
            inGraphDataFontColor:"#ccc",
            forceScale:"steps",
            scaleSteps : 10,
        };
        var pieoptions = baroptions;
        var stacked_baroptions= {
            graphTitle: title,
            graphTitleFontSize: 16,
            canvasBorders: true,
            canvasBordersWidth: 1,
            barDatasetSpacing: 0,
            barValueSpacing:0,
            rotateLabels: "smart",
            spaceBetweenBar : 4,
            animation : false,
            responsive: true,
            legend: false,
            highLight: true,
            xScaleLabelsMinimumWidth: 10,
            fmtXLabel: "text",
            fmtYLabel: "number",
            annotateLabel: "<%=v2+': '+v1+' '+v3%>",
            annotateDisplay: true,
            inGraphDataShow : true,
            inGraphDataFontColor: "#000",
            yAxisMinimumInterval:1,
            forceGraphMin : 0,
            graphMin:0,
            forceScale:"steps",
            scaleSteps : 10,
            scaleStepWidth : 1,
            yAxisUnitFontSize: 16,
            scaleFontColor: "#ddd",
            graphTitleFontColor: "#bbb",
        };
        if (res.labels.length == 0 || res.data.length == 0) {
        // for an empty graph
            var data_sets = {
                labels : [''],
                datasets: [{ data: [0]}]
            }
            new Chart(document.getElementById(canvas_id).getContext("2d")).Pie(data_sets, pieoptions);
            return false;
         }
        var data_sets = [];
        for (var i = 0; i < res.data.length; i++) {
            data_sets.push( {
                fillColor: colours[i % colours.length],
                strokeColor: colours[i % colours.length],
                data: res.data[i],
                title: res.labels[i]
            })
        }
        var data = {
           labels: res.fields,
           datasets: data_sets
        }
        if (res.data.length == 1) {
             baroptions.annotateLabel = "<%=v2+': '+v3%>"
             if (data.datasets[0].data.length > 10) {
                 baroptions['inGraphDataShow'] = false;
             }
             new Chart(document.getElementById(canvas_id).getContext("2d")).Bar(data, baroptions);
        } else {
             console.log(data);
             console.log(data.datasets.length);
              if (data.datasets.length > 10) {
                 stacked_baroptions['inGraphDataShow'] = false;
             }
             new Chart(document.getElementById(canvas_id).getContext("2d")).StackedBar(data, stacked_baroptions);
         }
    });
    return false;
}


function load_all_graphs()
{
//    var types = simple_types;
    var period = 'today';
    var to = null;
    var from = null;
    var host = $("#host_selector").find(":selected").val()
//    console.log(host, 'aoeuauae@##');

    if ($("#daily").is(":checked")) {period = 'today';}
    else if ($("#hourly").is(":checked")) {period = 'hour';}
    else if ($("#yesterday").is(":checked")) {period = 'yesterday';}
    else if ($("#weekly").is(":checked")) {period = 'week';}
    else if ($("#monthly").is(":checked")) {period = 'month';}
    else if ($("#custom").is(":checked")) {
        period = 'custom';
        from = $("#from_date").val();
        to = $("#to_date").val();
    }
    $("canvas").each(function() {
        load_graph($(this).attr('id'), $(this).attr("data-type"), $(this).attr("data-name"), period, to, from,
                   $(this).attr("data-title"), host);
    })
}


function set_hosts(selected)
{
//        console.log('hosts 1');
  $.ajax({
        url: script_root + '/hosts/',
        type: 'POST',
        data:  JSON.stringify({'selected': selected} ),
        cache: false,
        contentType: "application/json;charset=UTF-8",
    }).done(function(data) {
//        console.log('hosts');
        var res = JSON.parse(data);
//        console.log(res)
        $('#host_selector').html(res.html);
    });
}

$( document ).ready(function() {
       
//    add_items_lock = 0

    set_hosts()
    $('.dropdown-toggle').dropdown()

    $('body').css('background-image', 'url("' + script_root + '/static/img/background.gif")');
    $('body').css('background-size', 'contain');
    $("#custom").click(function() {
        $("#custom").prop("checked", true);
//         $('#timepicker').toggleClass('d-none');
     });

    $("[name^='timeperiod").click(function(event) {
       load_all_graphs()
    });
    calculate_height();

    $("#submit_custom").click(function() {
        $("#custom").prop("checked", true);
//        $('#timepicker').toggleClass('d-none');
        $('#custom').dropdown('toggle');
        load_all_graphs();
    });

    $("#host_selector").change(function() { load_all_graphs(); })
    $('#itemstablediv').scrollTop(0);
    load_all_graphs();
});
