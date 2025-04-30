import folium
import osmnx as ox

place = "Multimedia University, Cyberjaya, Malaysia"
center_latlon = ox.geocode(place)

sw_bound = [2.9245, 101.6380] 
ne_bound = [2.9285, 101.6425]  

campus_map = folium.Map(
    location=center_latlon,  
    zoom_start=17,           
    min_zoom=17,             
    max_zoom=19,             
    max_bounds=True,         
    dragging=False,          
    scrollWheelZoom=False    
)

campus_map.fit_bounds([sw_bound, ne_bound])  


folium.Marker(
    (2.9279902960943867, 101.64192865601028),
    popup="Multimedia University"
).add_to(campus_map)

folium.Marker(
    [2.9258793322585515, 101.64247957536298],
    popup="This is FCI (Faculty of Applied Communication)",
    tooltip="FAC"
).add_to(campus_map)

folium.Marker(
    [2.9291064152487003, 101.64058556358161],
    popup="This is FCI (Faculty of Computing & Informatics)",
    tooltip="FCI"
).add_to(campus_map)

# FOE - Faculty of Engineering
folium.Marker(
    [2.926426137695205, 101.64143107322919],
    popup="This is FOE (Faculty of Engineering)",
    tooltip="FOE"
).add_to(campus_map)

#FCA
folium.Marker(
    [2.926225644918432, 101.64235567376333],
    popup="This is FAC (Faculty of Cinematic Arts)",
    tooltip="FCA"
).add_to(campus_map)

# FOM - Faculty of Management
folium.Marker(
    [2.9300694160511584, 101.64100831840032],
    popup="This is FOM (Faculty of Management)",
    tooltip="FOM"
).add_to(campus_map)

# FCM - Faculty of Creative Multimedia
folium.Marker(
    [2.9261424404170127, 101.64317171677455],
    popup="This is FCM (Faculty of Creative Multimedia)",
    tooltip="FCM"
).add_to(campus_map)



map_html = campus_map.get_root().render()

full_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MMU Campus Map</title>
    <style>
        html, body {{
            margin: 0;
            padding: 0;
            height: 100%;
            width: 100%;
            display: flex;
            font-family: Arial, sans-serif;
        }}
        #map {{
            width: 55%;  
            height: 100vh; 
            flex: 1;  
            border-top-left-radius: 40% 30%;  
            border-bottom-right-radius: 40% 30%;  
            box-shadow: 0 6px 30px rgba(0, 0, 0, 0.15); 
        }}
    
    </style>
</head>
</html>
"""

with open("mmu_campus_map_custom_55.html", "w", encoding="utf-8") as f:
    f.write(full_html)

print("MMU campus map with smooth, organic shape and 55% screen width saved as 'mmu_campus_map_.html'")





