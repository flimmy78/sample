#include <string>
#include <vector>
#include <iostream>
#include <fstream>

using namespace std;

typedef struct tagListing
{
    string title;
    string image;
    string ref;
}LISTING;

int main(int argc ,char *argv[])
{
    int i = 0;
    ifstream fin(argv[1]); 
    string s;  

    vector <LISTING> listings;
    string title;
    string image;
    string ref;
    while( getline(fin,s) )
    {    
        if (i % 3 == 0)
        {
            ref = s;
        }
        else if (i % 3 == 1)
        {
            title = s;
        }
        else if (i % 3 == 2)
        {
            image = s;

            LISTING listing;
            listing.title = title;
            listing.image = image;
            listing.ref = ref;
            listings.push_back (listing);
        }
        i++;
    }

    for (vector<LISTING>::iterator it = listings.begin(); it != listings.end(); ++it)
    {
        for (vector<LISTING>::iterator it1 = listings.begin(); it1 != it; ++it1)
        {
            if (0 == it->title.compare (it1->title))
            {
                it->image = it1->image;
                it->ref = it1->ref;
            }
        }
    }

    for (vector<LISTING>::iterator it = listings.begin(); it != listings.end(); ++it)
    {
        cout <<  it->ref << endl;
        cout <<  it->title << endl;
        cout <<  it->image << endl;
    }

    return 0;
}

